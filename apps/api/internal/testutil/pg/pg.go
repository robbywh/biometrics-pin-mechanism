// Package pg provides throwaway Postgres databases for integration tests (ADR-009). A container is started once per
// test binary (testcontainers-go), migrated once as the owner role, and every test receives a fresh database cloned
// from that template. If TEST_DATABASE_URL is set (compose DB) it is used instead of starting a container.
// Tests connect as the least-privilege role `cryptoapp_api`, so privilege checks are real.
package pg

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpg "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/cryptoapp/api/migrations"
)

const (
	APIRole     = "cryptoapp_api"
	apiPassword = "test-api-password-not-a-secret"
	template    = "tmpl_cryptoapp"
)

var (
	once     sync.Once
	initErr  error
	adminDSN string // owner / superuser DSN to the maintenance db
	counter  atomic.Int64
	ctr      *tcpg.PostgresContainer
)

func setup() {
	ctx := context.Background()
	if v := os.Getenv("TEST_DATABASE_URL"); v != "" {
		adminDSN = v
	} else {
		c, err := tcpg.Run(ctx, "postgres:16-alpine",
			tcpg.WithDatabase("postgres"), tcpg.WithUsername("postgres"), tcpg.WithPassword("test-owner-password-not-a-secret"),
			testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(90*time.Second)))
		if err != nil {
			initErr = err
			return
		}
		ctr = c
		adminDSN, initErr = c.ConnectionString(ctx, "sslmode=disable")
		if initErr != nil {
			return
		}
	}
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		initErr = err
		return
	}
	defer func() { _ = admin.Close(ctx) }()
	// Roles are cluster-wide: create the least-privilege role before migrating.
	_, _ = admin.Exec(ctx, fmt.Sprintf(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='%s') THEN CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE; END IF; END $$`, APIRole, APIRole, apiPassword))
	_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+template)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+template); err != nil {
		initErr = err
		return
	}
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		initErr = err
		return
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, strings.Replace(withDB(adminDSN, template), "postgres://", "pgx5://", 1))
	if err != nil {
		initErr = err
		return
	}
	if err := m.Up(); err != nil {
		initErr = err
		return
	}
	_, _ = m.Close()
}

func withDB(dsn, db string) string {
	u, _ := url.Parse(dsn)
	u.Path = "/" + db
	return u.String()
}

func asRole(dsn, db string) string {
	u, _ := url.Parse(withDB(dsn, db))
	u.User = url.UserPassword(APIRole, apiPassword)
	return u.String()
}

// Pool is a fresh migrated database; it returns a pool connected as the API role plus the owner DSN of that database.
type DB struct {
	Pool     *pgxpool.Pool
	DSN      string // API-role DSN
	OwnerDSN string // owner DSN of this database (for assertions requiring privileges)
	Name     string
}

// New returns an isolated database cloned from the migrated template and drops it on cleanup.
func New(t testing.TB) *DB {
	t.Helper()
	once.Do(setup)
	if initErr != nil {
		t.Skipf("postgres unavailable (Docker not running?): %v", initErr)
	}
	ctx := context.Background()
	name := fmt.Sprintf("t_%d_%d", os.Getpid(), counter.Add(1))
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer func() { _ = admin.Close(ctx) }()
	if _, err := admin.Exec(ctx, fmt.Sprintf("CREATE DATABASE %s TEMPLATE %s", name, template)); err != nil {
		t.Fatalf("clone db: %v", err)
	}
	dsn := asRole(adminDSN, name)
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 20
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		a, err := pgx.Connect(ctx, adminDSN)
		if err == nil {
			_, _ = a.Exec(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)", name))
			_ = a.Close(ctx)
		}
	})
	return &DB{Pool: pool, DSN: dsn, OwnerDSN: withDB(adminDSN, name), Name: name}
}

// Terminate stops the shared container; call from TestMain.
func Terminate() {
	if ctr != nil {
		_ = ctr.Terminate(context.Background())
	}
}
