package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/cryptoapp/api/internal/apigen"
	"github.com/cryptoapp/api/internal/audit"
	"github.com/cryptoapp/api/internal/cryptomsg"
	"github.com/cryptoapp/api/internal/idem"
	"github.com/cryptoapp/api/internal/platform/httpx"
	"github.com/cryptoapp/api/internal/stepup"
	"github.com/cryptoapp/api/internal/store"
	"github.com/cryptoapp/api/internal/store/db"
)

const (
	maxBioFailures = 5
	epEnroll       = "POST /devices/{deviceId}/biometric/enroll"
)

// dummy key/signature used to burn ECDSA-shaped work on failure paths that have no real key (SEC-029, best effort).
var (
	dummyPub *ecdsa.PublicKey
	dummySig []byte
)

func init() {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dummyPub = &k.PublicKey
	h := sha256.Sum256([]byte("dummy"))
	dummySig, _ = ecdsa.SignASN1(rand.Reader, k, h[:])
}

func burnVerify() {
	_ = cryptomsg.VerifyDER(dummyPub, []byte("dummy-message"), dummySig[:len(dummySig)-1])
}

func challengeBody(c db.Challenge, purpose apigen.ChallengePurpose) apigen.Challenge {
	out := apigen.Challenge{ChallengeId: c.ID, Purpose: purpose, UserId: c.UserID, DeviceId: c.DeviceID,
		Nonce: cryptomsg.EncodeB64(c.Nonce), ExpiresAt: c.ExpiresAt.Unix()}
	if len(c.BoundHash) > 0 {
		out.BoundHash = ptr(cryptomsg.EncodeB64(c.BoundHash))
	}
	return out
}

// BiometricChallenge: non-oracular (SEC-029). Ineligible devices get a decoy with the identical shape.
func (s *Server) BiometricChallenge(ctx context.Context, req apigen.BiometricChallengeRequestObject) (apigen.BiometricChallengeResponseObject, error) {
	devID := req.Body.DeviceId
	if herr := s.limit(ctx, "bio-challenge-dev", devID.String(), s.Cfg.Limits.BioChallengeDevice, false); herr != nil {
		return nil, herr
	}
	now := s.Clk.Now()
	exp := now.Add(s.Cfg.ChallengeTTL)
	decoy := apigen.Challenge{ChallengeId: uuid.New(), Purpose: apigen.ChallengePurposeLogin, UserId: uuid.New(), DeviceId: devID,
		Nonce: cryptomsg.EncodeB64(randBytes(32)), ExpiresAt: exp.Unix()}

	dev, err := s.St.Q.GetDeviceByID(ctx, devID)
	if err != nil {
		if store.NotFound(err) {
			return apigen.BiometricChallenge200JSONResponse{Body: decoy}, nil
		}
		return nil, s.fail(ctx, "bioChallenge", err)
	}
	_, kerr := s.St.Q.GetActiveKey(ctx, devID)
	u, uerr := s.St.Q.GetUserByID(ctx, dev.UserID)
	if kerr != nil || uerr != nil || dev.RevokedAt != nil || u.HardLocked {
		for _, e := range []error{kerr, uerr} {
			if e != nil && !store.NotFound(e) {
				return nil, s.fail(ctx, "bioChallenge", e)
			}
		}
		return apigen.BiometricChallenge200JSONResponse{Body: decoy}, nil
	}
	nonce, err := cryptomsg.NewNonce()
	if err != nil {
		return nil, s.fail(ctx, "bioChallenge", err)
	}
	var ch db.Challenge
	err = s.St.InTx(ctx, func(q *db.Queries) error {
		if err := q.SupersedeChallenges(ctx, db.SupersedeChallengesParams{DeviceID: devID, Purpose: "login", ConsumedAt: ptr(now)}); err != nil {
			return err
		}
		var e error
		ch, e = q.InsertChallenge(ctx, db.InsertChallengeParams{ID: uuid.New(), UserID: dev.UserID, DeviceID: devID, Purpose: "login", Nonce: nonce, ExpiresAt: exp, CreatedAt: now})
		return e
	})
	if err != nil {
		return nil, s.fail(ctx, "bioChallenge", err)
	}
	return apigen.BiometricChallenge200JSONResponse{Body: challengeBody(ch, apigen.ChallengePurposeLogin)}, nil
}

// recordBioFailure counts a bad signature; the 5th consecutive one revokes the key (SEC-030). The PIN counter is untouched.
func (s *Server) recordBioFailure(ctx context.Context, key db.DeviceKey, dev db.Device) {
	n, err := s.St.Q.RecordBioFailure(ctx, key.ID)
	if err != nil {
		return
	}
	s.Audit.Emit(ctx, audit.Event{Type: audit.BioVerifyFail, UserID: &dev.UserID, DeviceID: &dev.ID, Result: "fail", Meta: map[string]any{"count": int(n)}})
	if int(n) < maxBioFailures {
		return
	}
	now := s.Clk.Now()
	_ = s.St.InTx(ctx, func(q *db.Queries) error {
		if r, err := q.RevokeActiveKey(ctx, db.RevokeActiveKeyParams{DeviceID: dev.ID, RevokedAt: ptr(now), RevokeReason: ptr("bio_failures")}); err != nil || r == 0 {
			return err
		}
		return q.InvalidateDeviceChallenges(ctx, db.InvalidateDeviceChallengesParams{DeviceID: dev.ID, ConsumedAt: ptr(now)})
	})
	s.Audit.Emit(ctx, audit.Event{Type: audit.BioKeyInvalidated, UserID: &dev.UserID, DeviceID: &dev.ID, Result: "fail", Meta: map[string]any{"reason": "bad_signatures", "fingerprint": cryptomsg.EncodeB64(key.Fingerprint)}})
}

// BiometricVerify: the signature is the credential. Every failure returns the same 401 body and headers.
func (s *Server) BiometricVerify(ctx context.Context, req apigen.BiometricVerifyRequestObject) (apigen.BiometricVerifyResponseObject, error) {
	b := req.Body
	if herr := s.limit(ctx, "bio-verify-dev", b.DeviceId.String(), s.Cfg.Limits.BioVerifyDevice, false); herr != nil {
		return nil, herr
	}
	fail := func() (apigen.BiometricVerifyResponseObject, error) { return nil, httpx.AuthFailed() }
	now := s.Clk.Now()
	sig, derr := cryptomsg.DecodeB64(b.Signature)
	dev, derr2 := s.St.Q.GetDeviceByID(ctx, b.DeviceId)
	if derr2 != nil && !store.NotFound(derr2) {
		return nil, s.fail(ctx, "bioVerify", derr2)
	}
	key, kerr := s.St.Q.GetActiveKey(ctx, b.DeviceId)
	if kerr != nil && !store.NotFound(kerr) {
		return nil, s.fail(ctx, "bioVerify", kerr)
	}
	haveKey := derr2 == nil && kerr == nil
	// Consume atomically on the first attempt (SEC-026), scoped to this device and the login purpose.
	ch, cerr := s.St.Q.ConsumeChallenge(ctx, db.ConsumeChallengeParams{ID: b.ChallengeId, DeviceID: b.DeviceId, Purpose: "login", ConsumedAt: ptr(now)})
	if cerr != nil && !store.NotFound(cerr) {
		return nil, s.fail(ctx, "bioVerify", cerr)
	}
	if !haveKey || cerr != nil || derr != nil {
		burnVerify()
		return fail()
	}
	u, err := s.St.Q.GetUserByID(ctx, dev.UserID)
	if err != nil || dev.RevokedAt != nil || u.HardLocked || ch.UserID != dev.UserID {
		burnVerify()
		return fail()
	}
	pub, perr := cryptomsg.ParseSPKI(key.Spki)
	msg := cryptomsg.ChallengeMessage(cryptomsg.PurposeLogin, ch.UserID.String(), ch.DeviceID.String(), ch.Nonce, ch.ExpiresAt.Unix(), nil)
	if perr != nil || !cryptomsg.VerifyDER(pub, msg, sig) {
		s.recordBioFailure(ctx, key, dev)
		return fail()
	}
	if key.BioFailCount != 0 {
		_ = s.St.Q.ResetBioFailures(ctx, key.ID)
	}
	var out apigen.SessionResponse
	err = s.St.InTx(ctx, func(q *db.Queries) error {
		recent, err := q.TakeRecentFailures(ctx, dev.UserID)
		if err != nil {
			return err
		}
		is, err := s.Auth.Create(ctx, q, dev.UserID, dev.ID, "bio")
		if err != nil {
			return err
		}
		if b.Risk != nil {
			s.storeRisk(ctx, q, dev.UserID, dev.ID, b.Risk, now)
		}
		_ = q.TouchDevice(ctx, db.TouchDeviceParams{ID: dev.ID, LastSeenAt: now})
		out, err = s.sessionResponse(ctx, q, is, ptr(int(recent)))
		return err
	})
	if err != nil {
		return nil, s.fail(ctx, "bioVerify", err)
	}
	httpx.InfoFrom(ctx).SetActor(dev.UserID.String(), dev.ID.String())
	s.Audit.Emit(ctx, audit.Event{Type: audit.LoginOK, UserID: &dev.UserID, DeviceID: &dev.ID, Meta: map[string]any{"method": "bio"}})
	return apigen.BiometricVerify200JSONResponse{Body: out}, nil
}

// ownDevice resolves {deviceId}: it must be the token's device and belong to the token's user, else 404.
func (s *Server) ownCurrentDevice(ctx context.Context, id uuid.UUID) (db.Device, *httpx.Error) {
	p := principal(ctx)
	if id != p.DeviceID {
		return db.Device{}, httpx.NotFound()
	}
	d, err := s.St.Q.GetDeviceForUser(ctx, db.GetDeviceForUserParams{ID: id, UserID: p.UserID})
	if err != nil || d.RevokedAt != nil {
		if err != nil && !store.NotFound(err) {
			return db.Device{}, s.fail(ctx, "device", err)
		}
		return db.Device{}, httpx.NotFound()
	}
	return d, nil
}

// BiometricEnrollChallenge (enrollment step 1) consumes the PIN step-up token (SEC-020, D-10).
func (s *Server) BiometricEnrollChallenge(ctx context.Context, req apigen.BiometricEnrollChallengeRequestObject) (apigen.BiometricEnrollChallengeResponseObject, error) {
	p := principal(ctx)
	dev, herr := s.ownCurrentDevice(ctx, req.DeviceId)
	if herr != nil {
		return nil, herr
	}
	tok, herr := requireStepUp(req.Params.XStepUpToken, "pin")
	if herr != nil {
		return nil, herr
	}
	if herr := s.limit(ctx, "enroll-challenge-user", p.UserID.String(), s.Cfg.Limits.EnrollUser, true); herr != nil {
		return nil, herr
	}
	now := s.Clk.Now()
	nonce, err := cryptomsg.NewNonce()
	if err != nil {
		return nil, s.fail(ctx, "enrollChallenge", err)
	}
	var ch db.Challenge
	err = s.St.InTx(ctx, func(q *db.Queries) error {
		out, proof, err := stepup.Consume(ctx, q, tok, p.UserID, p.SessionID, p.DeviceID, "enable_biometric", cryptomsg.ActionHash("enable_biometric", dev.ID.String()), now)
		if err != nil {
			return err
		}
		switch {
		case out == stepup.Mismatch:
			return &store.CommitErr{Err: stepUpInvalid()}
		case out == stepup.Invalid || proof != "pin": // biometric alone never enables biometrics
			return stepUpInvalid()
		}
		if err := q.SupersedeChallenges(ctx, db.SupersedeChallengesParams{DeviceID: dev.ID, Purpose: "enroll", ConsumedAt: ptr(now)}); err != nil {
			return err
		}
		ch, err = q.InsertChallenge(ctx, db.InsertChallengeParams{ID: uuid.New(), UserID: p.UserID, DeviceID: dev.ID, SessionID: ptr(p.SessionID), Purpose: "enroll",
			Nonce: nonce, ExpiresAt: now.Add(s.Cfg.ChallengeTTL), CreatedAt: now})
		return err
	})
	if err != nil {
		return nil, s.fail(ctx, "enrollChallenge", err)
	}
	return apigen.BiometricEnrollChallenge200JSONResponse{Body: challengeBody(ch, apigen.ChallengePurposeEnroll)}, nil
}

// BiometricEnroll (enrollment step 2): proof of possession over the enroll challenge with the NEW key.
func (s *Server) BiometricEnroll(ctx context.Context, req apigen.BiometricEnrollRequestObject) (apigen.BiometricEnrollResponseObject, error) {
	p := principal(ctx)
	dev, herr := s.ownCurrentDevice(ctx, req.DeviceId)
	if herr != nil {
		return nil, herr
	}
	b := req.Body
	k, herr := s.idemKey(p.UserID, epEnroll+"#"+dev.ID.String(), req.Params.IdempotencyKey, b)
	if herr != nil {
		return nil, herr
	}
	st, stored, herr := s.peekIdem(ctx, k)
	if herr != nil {
		return nil, herr
	}
	if r, herr := enrollReplay(st, stored); herr != nil || r != nil {
		if herr != nil {
			return nil, herr
		}
		return r, nil
	}
	if herr := s.limit(ctx, "enroll-user", p.UserID.String(), s.Cfg.Limits.EnrollUser, true); herr != nil {
		return nil, herr
	}
	now := s.Clk.Now()
	// Consume first, whatever happens next (SEC-026). Bound to user, session and device.
	ch, err := s.St.Q.ConsumeSessionChallenge(ctx, db.ConsumeSessionChallengeParams{ID: b.ChallengeId, DeviceID: dev.ID, Purpose: "enroll",
		UserID: p.UserID, SessionID: ptr(p.SessionID), ConsumedAt: ptr(now)})
	if err != nil {
		if store.NotFound(err) {
			burnVerify()
			return nil, httpx.AuthFailed()
		}
		return nil, s.fail(ctx, "enroll", err)
	}
	spki, derr := cryptomsg.DecodeB64(b.PublicKey)
	var pub *ecdsa.PublicKey
	if derr == nil {
		pub, derr = cryptomsg.ParseSPKI(spki)
	}
	if derr != nil {
		return nil, httpx.New(http.StatusUnprocessableEntity, "INVALID_PUBLIC_KEY")
	}
	sig, serr := cryptomsg.DecodeB64(b.Signature)
	msg := cryptomsg.ChallengeMessage(cryptomsg.PurposeEnroll, ch.UserID.String(), ch.DeviceID.String(), ch.Nonce, ch.ExpiresAt.Unix(), nil)
	if serr != nil || !cryptomsg.VerifyDER(pub, msg, sig) {
		return nil, httpx.AuthFailed()
	}
	// Attestation is stored but NOT verified in the demo: the stored type is therefore always "none" (SEC-022); the
	// claimed type goes to the audit event only. Self-reported level is untrusted.
	fp := cryptomsg.Fingerprint(spki)
	cool := now.Add(s.Cfg.CoolingOffDuration)
	var out apigen.BiometricEnrollResponse
	var replay apigen.BiometricEnrollResponseObject
	err = s.St.InTx(ctx, func(q *db.Queries) error {
		state, stored, err := idem.Begin(ctx, q, k, now)
		if err != nil {
			return err
		}
		if state != idem.Fresh {
			r, herr := enrollReplay(state, stored)
			if herr != nil {
				return herr
			}
			replay = r
			return nil
		}
		if _, err := q.RevokeActiveKey(ctx, db.RevokeActiveKeyParams{DeviceID: dev.ID, RevokedAt: ptr(now), RevokeReason: ptr("replaced")}); err != nil {
			return err
		}
		key, err := q.InsertDeviceKey(ctx, db.InsertDeviceKeyParams{ID: uuid.New(), DeviceID: dev.ID, Spki: spki, Fingerprint: fp, AttestationType: "none",
			KeySecurityLevel: string(b.Attestation.KeySecurityLevel), CoolingOffUntil: ptr(cool), CreatedAt: now})
		if err != nil {
			return err
		}
		out = apigen.BiometricEnrollResponse{KeyId: key.ID, KeyFingerprint: cryptomsg.EncodeB64(fp), BiometricEnabled: true, CoolingOffUntil: ptr(cool.Unix())}
		body, _ := json.Marshal(out)
		return idem.Complete(ctx, q, k, http.StatusCreated, body)
	})
	if err != nil {
		return nil, s.fail(ctx, "enroll", err)
	}
	if replay != nil {
		return replay, nil
	}
	s.Audit.Emit(ctx, audit.Event{Type: audit.BioEnrolled, UserID: &p.UserID, DeviceID: &dev.ID, Meta: map[string]any{"fingerprint": out.KeyFingerprint, "attestation": string(b.Attestation.Type), "level": string(b.Attestation.KeySecurityLevel)}})
	s.Audit.Emit(ctx, audit.Event{Type: audit.CoolingOffStarted, UserID: &p.UserID, DeviceID: &dev.ID, Meta: map[string]any{"reason": "bio_enroll"}})
	return apigen.BiometricEnroll201JSONResponse(out), nil
}

func enrollReplay(st idem.State, stored *idem.Stored) (apigen.BiometricEnrollResponseObject, *httpx.Error) {
	switch st {
	case idem.Reused:
		return nil, errReused()
	case idem.Replay:
		var r apigen.BiometricEnrollResponse
		if stored == nil || json.Unmarshal(stored.Body, &r) != nil {
			return nil, httpx.Internal()
		}
		return apigen.BiometricEnroll200JSONResponse(r), nil
	}
	return nil, nil
}

// BiometricDisable: allowed within 5 minutes of the session's last unlock, otherwise the client must re-unlock (D-02).
func (s *Server) BiometricDisable(ctx context.Context, req apigen.BiometricDisableRequestObject) (apigen.BiometricDisableResponseObject, error) {
	p := principal(ctx)
	d, err := s.St.Q.GetDeviceForUser(ctx, db.GetDeviceForUserParams{ID: req.DeviceId, UserID: p.UserID})
	if err != nil || d.RevokedAt != nil {
		if err != nil && !store.NotFound(err) {
			return nil, s.fail(ctx, "bioDisable", err)
		}
		return nil, httpx.NotFound()
	}
	now := s.Clk.Now()
	if now.Sub(p.LastUnlock) > 5*time.Minute {
		e := httpx.New(http.StatusForbidden, "STEPUP_REQUIRED")
		e.Required = "pin"
		return nil, e
	}
	var revoked int64
	err = s.St.InTx(ctx, func(q *db.Queries) error {
		var e error
		if revoked, e = q.RevokeActiveKey(ctx, db.RevokeActiveKeyParams{DeviceID: d.ID, RevokedAt: ptr(now), RevokeReason: ptr("disabled")}); e != nil {
			return e
		}
		return q.InvalidateDeviceChallenges(ctx, db.InvalidateDeviceChallengesParams{DeviceID: d.ID, ConsumedAt: ptr(now)})
	})
	if err != nil {
		return nil, s.fail(ctx, "bioDisable", err)
	}
	if revoked > 0 {
		s.Audit.Emit(ctx, audit.Event{Type: audit.BioDisabled, UserID: &p.UserID, DeviceID: &d.ID})
	}
	return apigen.BiometricDisable204Response{}, nil
}
