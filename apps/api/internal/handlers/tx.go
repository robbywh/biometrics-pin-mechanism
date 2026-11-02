package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/cryptoapp/api/internal/apigen"
	"github.com/cryptoapp/api/internal/audit"
	"github.com/cryptoapp/api/internal/cryptomsg"
	"github.com/cryptoapp/api/internal/idem"
	"github.com/cryptoapp/api/internal/platform/httpx"
	"github.com/cryptoapp/api/internal/stepup"
	"github.com/cryptoapp/api/internal/store"
	"github.com/cryptoapp/api/internal/store/db"
)

const epTx = "POST /transactions"

func isUniqueViolation(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

// CreateTransaction: the server recomputes the canonical hash from THIS body; the step-up token is consumed in the
// same DB transaction as the debit and the transaction insert (SEC-039, SEC-040, SEC-044).
func (s *Server) CreateTransaction(ctx context.Context, req apigen.CreateTransactionRequestObject) (apigen.CreateTransactionResponseObject, error) {
	p := principal(ctx)
	b := req.Body
	if herr := s.limit(ctx, "tx-user", p.UserID.String(), s.Cfg.Limits.TxUser, true); herr != nil {
		return nil, herr
	}
	k, herr := s.idemKey(p.UserID, epTx, req.Params.IdempotencyKey, b)
	if herr != nil {
		return nil, herr
	}
	tok, herr := requireStepUp(derefStr(req.Params.XStepUpToken), "")
	st, stored, perr := s.peekIdem(ctx, k)
	if perr != nil {
		return nil, perr
	}
	if r, rerr := txReplay(st, stored); rerr != nil || r != nil { // a replay is answered even though the token is spent
		if rerr != nil {
			return nil, rerr
		}
		return r, nil
	}
	if herr != nil {
		return nil, herr
	}
	now := s.Clk.Now()
	f, hash, usd, herr := s.txFields(*b, now)
	if herr != nil {
		return nil, herr
	}
	u, err := s.St.Q.GetUserByID(ctx, p.UserID)
	if err != nil {
		return nil, s.fail(ctx, "createTransaction", err)
	}
	dev, err := s.St.Q.GetDeviceForUser(ctx, db.GetDeviceForUserParams{ID: p.DeviceID, UserID: p.UserID})
	if err != nil {
		return nil, s.fail(ctx, "createTransaction", err)
	}
	var key *db.DeviceKey
	if kk, err := s.St.Q.GetActiveKey(ctx, p.DeviceID); err == nil {
		key = &kk
	} else if !store.NotFound(err) {
		return nil, s.fail(ctx, "createTransaction", err)
	}
	cooling, until := s.coolingActive(u, dev, key, now)
	if cooling && usd.Cmp(s.Cfg.CoolingOffMax) > 0 {
		return nil, coolingOffErr(until, now)
	}
	amt, _ := cryptomsg.NormalizeDecimal(f.Amount)
	fee, _ := cryptomsg.NormalizeDecimal(f.Fee)
	debit := decimalString(new(big.Rat).Add(ratFromString(amt), ratFromString(fee)))
	txID := uuid.New()
	var resp apigen.TransactionResponse
	var replay apigen.CreateTransactionResponseObject
	err = s.St.InTx(ctx, func(q *db.Queries) error {
		// 0. user-row lock FIRST (before any statement that takes a FOR KEY SHARE on users via an FK: avoids lock-order deadlocks),
		// so concurrent submissions are serialised and cannot slip past the rolling-window sums.
		if _, err := q.LockUserRow(ctx, p.UserID); err != nil {
			return err
		}
		// 1. idempotency first: a replay must not be turned into 403 by the already-spent token.
		state, stored, err := idem.Begin(ctx, q, k, now)
		if err != nil {
			return err
		}
		if state != idem.Fresh {
			r, herr := txReplay(state, stored)
			if herr != nil {
				return herr
			}
			replay = r
			return nil
		}
		// 1b. aggregate limits (SEC-069) under the user-row lock taken first in this tx
		if cooling {
			if herr, err := s.coolingAggregate(ctx, q, p.UserID, usd, until, now); err != nil || herr != nil {
				if err == nil {
					err = herr
				}
				return err
			}
		}
		// 2. spend the step-up token
		out, proof, err := stepup.Consume(ctx, q, tok, p.UserID, p.SessionID, p.DeviceID, "transaction", hash, now)
		if err != nil {
			return err
		}
		if out == stepup.Mismatch { // valid token, different transaction: burn it, forget the idempotency record
			if err := idem.Abort(ctx, q, k); err != nil {
				return err
			}
			return &store.CommitErr{Err: stepUpInvalid()}
		}
		if out == stepup.Invalid {
			return stepUpInvalid()
		}
		if proof == "bio" { // the aggregate bio-only allowance (H-01): a biometric proof cannot exceed BIO_ONLY_MAX per window
			over, err := s.bioOverAggregate(ctx, q, p.UserID, usd, now)
			if err != nil {
				return err
			}
			if over {
				e := httpx.New(http.StatusForbidden, "STEPUP_REQUIRED")
				e.Required = "pin"
				return e
			}
		}
		if s.Hooks.AfterStepUpConsume != nil {
			if err := s.Hooks.AfterStepUpConsume(); err != nil {
				return err
			}
		}
		// 3. exact decimal debit (amount + fee), never below zero
		if _, err := q.DebitBalance(ctx, db.DebitBalanceParams{UserID: p.UserID, Asset: f.Asset, Column3: debit}); err != nil {
			if store.NotFound(err) {
				return httpx.New(http.StatusUnprocessableEntity, "INSUFFICIENT_FUNDS")
			}
			return err
		}
		nonce := b.TxNonce
		if _, err := q.InsertTransaction(ctx, db.InsertTransactionParams{ID: txID, UserID: p.UserID, SessionID: p.SessionID, DeviceID: p.DeviceID,
			StepUpTokenHash: tokenHash(tok), TxNonce: nonce, TxHash: hash, Asset: f.Asset, Network: f.Network, Destination: f.Destination,
			Column11: amt, Column12: fee, CreatedAt: now}); err != nil {
			if isUniqueViolation(err) { // same txNonce again with a fresh step-up token: no second transaction
				return errReplay()
			}
			return err
		}
		resp = apigen.TransactionResponse{TransactionId: txID, Status: "accepted_mock", TxHash: cryptomsg.EncodeB64(hash)}
		body, _ := json.Marshal(resp)
		return idem.Complete(ctx, q, k, http.StatusAccepted, body)
	})
	if err != nil {
		return nil, s.fail(ctx, "createTransaction", err)
	}
	if replay != nil {
		return replay, nil
	}
	s.Audit.Emit(ctx, audit.Event{Type: audit.TxCreated, UserID: &p.UserID, DeviceID: &p.DeviceID, Meta: map[string]any{"count": 1}})
	return apigen.CreateTransaction202JSONResponse(resp), nil
}

func txReplay(st idem.State, stored *idem.Stored) (apigen.CreateTransactionResponseObject, *httpx.Error) {
	switch st {
	case idem.Reused:
		return nil, errReused()
	case idem.Replay:
		var r apigen.TransactionResponse
		if stored == nil || json.Unmarshal(stored.Body, &r) != nil {
			return nil, httpx.Internal()
		}
		return apigen.CreateTransaction202JSONResponse(r), nil
	}
	return nil, nil
}

func (s *Server) GetDashboard(ctx context.Context, _ apigen.GetDashboardRequestObject) (apigen.GetDashboardResponseObject, error) {
	p := principal(ctx)
	rows, err := s.St.Q.GetBalances(ctx, p.UserID)
	if err != nil {
		return nil, s.fail(ctx, "dashboard", err)
	}
	total := new(big.Rat)
	out := apigen.Dashboard{Currency: "USD", Balances: make([]apigen.Balance, 0, len(rows))}
	for _, r := range rows {
		amt := ratFromString(r.Amount)
		val := new(big.Rat)
		if pr := s.Cfg.Prices[r.Asset]; pr != nil {
			val.Mul(amt, pr)
		}
		total.Add(total, val)
		out.Balances = append(out.Balances, apigen.Balance{Asset: apigen.BalanceAsset(r.Asset), Amount: decimalString(amt), Value: val.FloatString(2)})
	}
	out.TotalValue = total.FloatString(2)
	return apigen.GetDashboard200JSONResponse{Body: out}, nil
}

func coolingOffErr(until, now time.Time) *httpx.Error {
	e := httpx.New(http.StatusForbidden, "COOLING_OFF")
	e.RetryAfter = ptr(int(until.Sub(now).Seconds() + 0.999))
	return e
}

// coolingAggregate enforces COOLING_OFF_MAX and COOLING_OFF_MAX_TX as ROLLING-WINDOW aggregates (H-01).
// coolingAggregate enforces COOLING_OFF_MAX and COOLING_OFF_MAX_TX as ROLLING-WINDOW aggregates (SEC-069, window COOLING_OFF_WINDOW).
func (s *Server) coolingAggregate(ctx context.Context, q *db.Queries, user uuid.UUID, usd *big.Rat, until, now time.Time) (*httpx.Error, error) {
	sum, n, err := s.sumSince(ctx, q, user, now.Add(-s.Cfg.CoolingOffWindow), "")
	if err != nil {
		return nil, err
	}
	if new(big.Rat).Add(sum, usd).Cmp(s.Cfg.CoolingOffMax) > 0 || n+1 > int64(s.Cfg.CoolingOffMaxTx) {
		return coolingOffErr(until, now), nil
	}
	return nil, nil
}

// bioOverAggregate reports whether the trailing sum of BIOMETRIC-approved value (window BIO_ONLY_WINDOW) plus usd exceeds BIO_ONLY_MAX.
func (s *Server) bioOverAggregate(ctx context.Context, q *db.Queries, user uuid.UUID, usd *big.Rat, now time.Time) (bool, error) {
	sum, _, err := s.sumSince(ctx, q, user, now.Add(-s.Cfg.BioOnlyWindow), "bio")
	if err != nil {
		return false, err
	}
	return new(big.Rat).Add(sum, usd).Cmp(s.Cfg.BioOnlyMax) > 0, nil
}

// sumSince returns the mock-USD value and count of the user's transactions since `since` (exact big.Rat arithmetic).
func (s *Server) sumSince(ctx context.Context, q *db.Queries, user uuid.UUID, since time.Time, proof string) (*big.Rat, int64, error) {
	rows, err := q.SumTxByAsset(ctx, db.SumTxByAssetParams{UserID: user, CreatedAt: since, Proof: proof})
	if err != nil {
		return nil, 0, err
	}
	total, n := new(big.Rat), int64(0)
	for _, r := range rows {
		if price := s.Cfg.Prices[r.Asset]; price != nil {
			total.Add(total, new(big.Rat).Mul(ratFromString(r.Total), price))
		}
		n += r.N
	}
	return total, n, nil
}
