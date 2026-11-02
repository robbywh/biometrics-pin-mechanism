// Package migrations embeds the SQL migrations (golang-migrate format) for cmd/migrate and the test helper.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
