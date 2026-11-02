// Package store wraps the pgx pool and the sqlc-generated queries. All multi-step state changes go through InTx
// (READ COMMITTED) and rely on single-statement compare-and-set or row locks (SEC-008, SEC-026, SEC-032, SEC-066).
// No state is kept in process memory.
package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cryptoapp/api/internal/store/db"
)

type Store struct {
	Pool *pgxpool.Pool
	Q    *db.Queries
}

func New(pool *pgxpool.Pool) *Store { return &Store{Pool: pool, Q: db.New(pool)} }

func (s *Store) Ping(ctx context.Context) error { return s.Pool.Ping(ctx) }

// InTx runs fn in one READ COMMITTED transaction; any error or panic rolls back.
func (s *Store) InTx(ctx context.Context, fn func(q *db.Queries) error) (err error) {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(context.Background())
			panic(p)
		}
		if err != nil {
			_ = tx.Rollback(context.Background())
		}
	}()
	if err = fn(s.Q.WithTx(tx)); err != nil {
		var ce *CommitErr
		if errors.As(err, &ce) { // commit what was done so far (e.g. a burned step-up token), then report ce.Err
			if cerr := tx.Commit(ctx); cerr != nil {
				err = cerr
				return err
			}
			err = nil
			return ce.Err
		}
		return err
	}
	return tx.Commit(ctx)
}

// CommitErr makes InTx COMMIT the transaction and still return Err to the caller. Used where a failed request must
// still persist a security-relevant effect (a step-up token that was valid but mismatched is burned).
type CommitErr struct{ Err error }

func (c *CommitErr) Error() string { return c.Err.Error() }
func (c *CommitErr) Unwrap() error { return c.Err }

// NotFound reports pgx.ErrNoRows.
func NotFound(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
