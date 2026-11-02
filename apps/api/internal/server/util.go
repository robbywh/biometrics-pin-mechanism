package server

import (
	"strconv"

	"github.com/jackc/pgx/v5/pgtype"
)

func itoa(n int) string { return strconv.Itoa(n) }

func numeric(s string) pgtype.Numeric {
	var n pgtype.Numeric
	_ = n.Scan(s)
	return n
}
