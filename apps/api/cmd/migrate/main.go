// Command migrate applies or reverts migrations. It is the ONLY place that reads DATABASE_MIGRATE_URL (owner role).
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"

	"github.com/cryptoapp/api/migrations"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: migrate up | down [n]")
		os.Exit(2)
	}
	url := os.Getenv("DATABASE_MIGRATE_URL")
	if url == "" || strings.Contains(url, "CHANGE_ME") {
		fmt.Fprintln(os.Stderr, "DATABASE_MIGRATE_URL is required (owner role) and must not be a placeholder")
		os.Exit(1)
	}
	url = strings.Replace(url, "postgres://", "pgx5://", 1)
	url = strings.Replace(url, "postgresql://", "pgx5://", 1)
	if os.Args[1] == "purge-audit" { // owner role only: the API role has no DELETE on audit_events (append-only)
		days := 30
		if len(os.Args) > 2 {
			var perr error
			if days, perr = strconv.Atoi(os.Args[2]); perr != nil || days < 1 {
				fail(errors.New("purge-audit needs a positive number of days"))
			}
		}
		purgeAudit(os.Getenv("DATABASE_MIGRATE_URL"), days)
		return
	}
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		fail(err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, url)
	if err != nil {
		fail(errors.New("cannot open migration database"))
	}
	switch os.Args[1] {
	case "up":
		err = m.Up()
	case "down":
		n := 1
		if len(os.Args) > 2 {
			if n, err = strconv.Atoi(os.Args[2]); err != nil || n < 1 {
				fail(errors.New("down needs a positive step count"))
			}
		}
		err = m.Steps(-n)
	default:
		fail(errors.New("unknown command"))
	}
	if err != nil && !errors.Is(err, migrate.ErrNoChange) {
		fail(err)
	}
	fmt.Println("ok")
}

func purgeAudit(url string, days int) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		fail(errors.New("cannot connect"))
	}
	defer func() { _ = conn.Close(ctx) }()
	tag, err := conn.Exec(ctx, "DELETE FROM audit_events WHERE ts < now() - make_interval(days => $1)", days)
	if err != nil {
		fail(errors.New("purge failed"))
	}
	fmt.Printf("purged %d audit rows\n", tag.RowsAffected())
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "migrate:", err)
	os.Exit(1)
}
