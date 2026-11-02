package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/cryptoapp/api/internal/apigen"
	"github.com/cryptoapp/api/internal/audit"
	"github.com/cryptoapp/api/internal/cryptomsg"
	"github.com/cryptoapp/api/internal/lockout"
	"github.com/cryptoapp/api/internal/platform/httpx"
	"github.com/cryptoapp/api/internal/stepup"
	"github.com/cryptoapp/api/internal/store"
	"github.com/cryptoapp/api/internal/store/db"
)

func strictDecode(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(v)
}

// txFields converts and validates the transaction body (semantic checks, 422 on failure). It returns the canonical
// hash and the amount in mock USD.
func (s *Server) txFields(t apigen.TransactionFields, now time.Time) (cryptomsg.TxFields, []byte, *big.Rat, *httpx.Error) {
	f := cryptomsg.TxFields{Asset: string(t.Asset), Network: string(t.Network), Destination: t.Destination, Amount: t.Amount, Fee: t.Fee,
		TxNonce: t.TxNonce.String(), Expiry: t.Expiry}
	if t.Expiry <= now.Unix() || t.Expiry > now.Add(600*time.Second).Unix() {
		return f, nil, nil, httpx.Unprocessable()
	}
	h, err := cryptomsg.TxHash(f)
	if err != nil {
		return f, nil, nil, httpx.Unprocessable()
	}
	amt, _ := cryptomsg.NormalizeDecimal(f.Amount)
	r := ratFromString(amt)
	if r.Sign() <= 0 {
		return f, nil, nil, httpx.Unprocessable()
	}
	price := s.Cfg.Prices[f.Asset]
	if price == nil {
		return f, nil, nil, httpx.Unprocessable()
	}
	return f, h, new(big.Rat).Mul(r, price), nil
}

func (s *Server) StepupChallenge(ctx context.Context, req apigen.StepupChallengeRequestObject) (apigen.StepupChallengeResponseObject, error) {
	p := principal(ctx)
	if herr := s.limit(ctx, "stepup-user", p.UserID.String(), s.Cfg.Limits.StepUpUser, true); herr != nil {
		return nil, herr
	}
	raw, err := req.Body.MarshalJSON()
	if err != nil {
		return nil, httpx.Validation()
	}
	var head struct {
		Action string `json:"action"`
	}
	_ = json.Unmarshal(raw, &head)
	now := s.Clk.Now()

	u, err := s.St.Q.GetUserByID(ctx, p.UserID)
	if err != nil {
		return nil, s.fail(ctx, "stepupChallenge", err)
	}
	dev, err := s.St.Q.GetDeviceForUser(ctx, db.GetDeviceForUserParams{ID: p.DeviceID, UserID: p.UserID})
	if err != nil {
		return nil, s.fail(ctx, "stepupChallenge", err)
	}
	var key *db.DeviceKey
	if k, err := s.St.Q.GetActiveKey(ctx, p.DeviceID); err == nil {
		key = &k
	} else if !store.NotFound(err) {
		return nil, s.fail(ctx, "stepupChallenge", err)
	}

	var bound []byte
	var required string
	var txHash []byte
	var summary apigen.StepUpSummary
	switch head.Action {
	case "transaction":
		var tr apigen.StepUpTxRequest
		if strictDecode(raw, &tr) != nil {
			return nil, httpx.Validation()
		}
		f, h, usd, herr := s.txFields(tr.Tx, now)
		if herr != nil {
			return nil, herr
		}
		cooling, until := s.coolingActive(u, dev, key, now)
		if cooling && usd.Cmp(s.Cfg.CoolingOffMax) > 0 {
			e := httpx.New(http.StatusForbidden, "COOLING_OFF")
			e.RetryAfter = ptr(int(until.Sub(now).Seconds() + 0.999))
			return nil, e
		}
		keyCool := key != nil && key.CoolingOffUntil != nil && key.CoolingOffUntil.After(now)
		required = stepup.RequiredForTx(stepup.Policy{KeyPresent: key != nil, KeyInCoolingOff: keyCool,
			AttestationNone: key != nil && key.AttestationType == "none", Prod: s.Cfg.Env == "prod", OverBioMax: usd.Cmp(s.Cfg.BioOnlyMax) > 0})
		bound, txHash = h, h
		amt, _ := cryptomsg.NormalizeDecimal(f.Amount)
		fee, _ := cryptomsg.NormalizeDecimal(f.Fee)
		summary = apigen.StepUpSummary{Title: fmt.Sprintf("Send %s %s", amt, f.Asset),
			Lines: []string{"To: " + f.Destination, "Network: " + f.Network, fmt.Sprintf("Fee: %s %s", fee, f.Asset)}}
	case "enable_biometric", "revoke_device":
		var tr apigen.StepUpTargetRequest
		if strictDecode(raw, &tr) != nil {
			return nil, httpx.Validation()
		}
		target := tr.TargetDeviceId
		td, err := s.St.Q.GetDeviceForUser(ctx, db.GetDeviceForUserParams{ID: target, UserID: p.UserID})
		if err != nil || td.RevokedAt != nil || (head.Action == "enable_biometric" && target != p.DeviceID) {
			if err != nil && !store.NotFound(err) {
				return nil, s.fail(ctx, "stepupChallenge", err)
			}
			return nil, httpx.NotFound()
		}
		required = "pin"
		bound = cryptomsg.ActionHash(head.Action, target.String())
		if head.Action == "enable_biometric" {
			summary = apigen.StepUpSummary{Title: "Enable biometric unlock", Lines: []string{"Device: " + td.Name}}
		} else {
			summary = apigen.StepUpSummary{Title: "Remove device", Lines: []string{"Device: " + td.Name}}
		}
	default:
		return nil, httpx.Validation()
	}

	nonce, err := cryptomsg.NewNonce()
	if err != nil {
		return nil, s.fail(ctx, "stepupChallenge", err)
	}
	var ch db.Challenge
	err = s.St.InTx(ctx, func(q *db.Queries) error {
		// One live step-up challenge: a new request supersedes the previous one (SEC-025).
		if err := q.SupersedeChallenges(ctx, db.SupersedeChallengesParams{DeviceID: p.DeviceID, Purpose: "stepup", ConsumedAt: ptr(now)}); err != nil {
			return err
		}
		var e error
		ch, e = q.InsertChallenge(ctx, db.InsertChallengeParams{ID: uuid.New(), UserID: p.UserID, DeviceID: p.DeviceID, SessionID: ptr(p.SessionID), Purpose: "stepup",
			Action: ptr(head.Action), Nonce: nonce, BoundHash: bound, RequiredProof: ptr(required), ExpiresAt: now.Add(s.Cfg.ChallengeTTL), CreatedAt: now})
		return e
	})
	if err != nil {
		return nil, s.fail(ctx, "stepupChallenge", err)
	}
	out := apigen.StepUpChallenge{ChallengeId: ch.ID, Purpose: "stepup", Action: apigen.StepUpChallengeAction(head.Action), UserId: ch.UserID, DeviceId: ch.DeviceID,
		Nonce: cryptomsg.EncodeB64(nonce), ExpiresAt: ch.ExpiresAt.Unix(), BoundHash: cryptomsg.EncodeB64(bound),
		Required: apigen.StepUpChallengeRequired(required), Summary: summary}
	if txHash != nil {
		out.TxHash = ptr(cryptomsg.EncodeB64(txHash))
	}
	return apigen.StepupChallenge200JSONResponse{Body: out}, nil
}

func (s *Server) StepupVerify(ctx context.Context, req apigen.StepupVerifyRequestObject) (apigen.StepupVerifyResponseObject, error) {
	p := principal(ctx)
	if herr := s.limit(ctx, "stepup-user", p.UserID.String(), s.Cfg.Limits.StepUpUser, true); herr != nil {
		return nil, herr
	}
	raw, err := req.Body.MarshalJSON()
	if err != nil {
		return nil, httpx.Validation()
	}
	var probe map[string]json.RawMessage
	_ = json.Unmarshal(raw, &probe)
	_, hasPin := probe["pin"]
	_, hasSig := probe["signature"]
	if hasPin == hasSig { // ambiguous or empty: exactly one proof is allowed
		return nil, httpx.Validation()
	}
	var challengeID uuid.UUID
	var pinPlain, sigB64 string
	if hasPin {
		var v apigen.StepUpVerifyPin
		if strictDecode(raw, &v) != nil || v.Pin == nil {
			return nil, httpx.Validation()
		}
		challengeID, pinPlain = v.ChallengeId, *v.Pin
	} else {
		var v apigen.StepUpVerifyBio
		if strictDecode(raw, &v) != nil {
			return nil, httpx.Validation()
		}
		challengeID, sigB64 = v.ChallengeId, v.Signature
	}
	now := s.Clk.Now()
	// Consume FIRST, atomically; any later failure (wrong PIN, bad signature) needs a fresh challenge (D-08).
	ch, err := s.St.Q.ConsumeSessionChallenge(ctx, db.ConsumeSessionChallengeParams{ID: challengeID, DeviceID: p.DeviceID, Purpose: "stepup",
		UserID: p.UserID, SessionID: ptr(p.SessionID), ConsumedAt: ptr(now)})
	if err != nil {
		if store.NotFound(err) {
			burnVerify()
			return nil, httpx.AuthFailed()
		}
		return nil, s.fail(ctx, "stepupVerify", err)
	}
	required := ""
	if ch.RequiredProof != nil {
		required = *ch.RequiredProof
	}
	proof := "pin"
	if hasSig {
		proof = "bio"
	}
	if required != "either" && required != proof {
		e := httpx.New(http.StatusForbidden, "STEPUP_REQUIRED")
		e.Required = required
		return nil, e
	}
	action := ""
	if ch.Action != nil {
		action = *ch.Action
	}
	if proof == "pin" {
		res, err := s.Lock.Attempt(ctx, p.UserID, pinPlain, &p.DeviceID, false)
		if err != nil {
			return nil, s.fail(ctx, "stepupVerify", err)
		}
		if res.Kind != lockout.OK {
			s.Audit.Emit(ctx, audit.Event{Type: audit.StepUpFail, UserID: &p.UserID, DeviceID: &p.DeviceID, Result: "fail", Meta: map[string]any{"proof": "pin", "action": action}})
			return nil, lockout.Error(res, now)
		}
	} else {
		key, kerr := s.St.Q.GetActiveKey(ctx, p.DeviceID)
		sig, derr := cryptomsg.DecodeB64(sigB64)
		if kerr != nil || derr != nil {
			if kerr != nil && !store.NotFound(kerr) {
				return nil, s.fail(ctx, "stepupVerify", kerr)
			}
			burnVerify()
			return nil, httpx.AuthFailed()
		}
		pub, perr := cryptomsg.ParseSPKI(key.Spki)
		msg := cryptomsg.ChallengeMessage(cryptomsg.PurposeStepUp, ch.UserID.String(), ch.DeviceID.String(), ch.Nonce, ch.ExpiresAt.Unix(), ch.BoundHash)
		if perr != nil || !cryptomsg.VerifyDER(pub, msg, sig) {
			if dev, err := s.St.Q.GetDeviceByID(ctx, p.DeviceID); err == nil {
				s.recordBioFailure(ctx, key, dev)
			}
			s.Audit.Emit(ctx, audit.Event{Type: audit.StepUpFail, UserID: &p.UserID, DeviceID: &p.DeviceID, Result: "fail", Meta: map[string]any{"proof": "bio", "action": action}})
			return nil, httpx.AuthFailed()
		}
	}
	var token string
	var expires int
	err = s.St.InTx(ctx, func(q *db.Queries) error {
		var e error
		token, expires, e = stepup.Mint(ctx, q, p.UserID, p.SessionID, p.DeviceID, action, ch.BoundHash, proof, s.Cfg.StepUpTTL, now)
		if e != nil {
			return e
		}
		return q.SetSessionUnlock(ctx, db.SetSessionUnlockParams{ID: p.SessionID, LastUnlockAt: now})
	})
	if err != nil {
		return nil, s.fail(ctx, "stepupVerify", err)
	}
	s.Audit.Emit(ctx, audit.Event{Type: audit.StepUpOK, UserID: &p.UserID, DeviceID: &p.DeviceID, Meta: map[string]any{"proof": proof, "action": action}})
	return apigen.StepupVerify200JSONResponse{Body: apigen.StepUpTokenResponse{StepUpToken: token, ExpiresIn: expires}}, nil
}
