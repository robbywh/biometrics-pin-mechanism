SQLC_VERSION := v1.31.1
LINT_VERSION := v2.15.0
VULN_VERSION := v1.9.0
SPEC := ../../docs/features/biometric-pin-login/openapi.yaml
ENVFILE := ../../.env

.PHONY: gen build run test lint contract-test vulncheck migrate migrate-down

gen:
	go tool oapi-codegen -config oapi-codegen.yaml $(SPEC)
	go run github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION) generate
	gofmt -w internal/apigen internal/store/db

build:
	go build -o bin/api ./cmd/api
	go build -o bin/migrate ./cmd/migrate

run:
	@set -a; [ -f $(ENVFILE) ] && . $(ENVFILE); set +a; go run ./cmd/api

test:
	go vet ./...
	go test -race -timeout 30m ./...

contract-test:
	# whole e2e package (every response is validated against the canonical openapi.yaml; TestZContractCoverage runs last)
	# plus the shared byte-layout vectors (docs/features/biometric-pin-login/vectors/vectors.json)
	go test -race -count=1 -timeout 30m ./internal/e2e/...
	go test -race -count=1 -run 'TestSharedVectors' ./internal/cryptomsg/...

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(LINT_VERSION) run --config ../../.golangci.yml ./...

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@$(VULN_VERSION) ./...

migrate:
	@set -a; [ -f $(ENVFILE) ] && . $(ENVFILE); set +a; go run ./cmd/migrate up

migrate-down:
	@set -a; [ -f $(ENVFILE) ] && . $(ENVFILE); set +a; go run ./cmd/migrate down 1
