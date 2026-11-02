package server

import (
	"context"
	"log/slog"
	"time"

	"github.com/cryptoapp/api/internal/clock"
	"github.com/cryptoapp/api/internal/store"
)

// PurgeOnce removes expired idempotency records (24 h), unbound expired bootstrap tokens and challenges older than 24 h.
func PurgeOnce(ctx context.Context, st *store.Store, clk clock.Clock) (idem, boot, chal int64, err error) {
	now := clk.Now()
	if idem, err = st.Q.PurgeIdempotency(ctx, now); err != nil {
		return
	}
	if boot, err = st.Q.PurgeExpiredBootstrap(ctx, now); err != nil {
		return
	}
	chal, err = st.Q.PurgeChallenges(ctx, now.Add(-24*time.Hour))
	return
}

// RunMaintenance purges hourly until ctx is cancelled.
func RunMaintenance(ctx context.Context, st *store.Store, clk clock.Clock, log *slog.Logger) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, _, _, err := PurgeOnce(ctx, st, clk); err != nil {
				log.Error("maintenance purge failed", "component", "maintenance", "err_class", "store")
			}
		}
	}
}
