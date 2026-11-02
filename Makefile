# Root Makefile: forwards only. Real logic lives in apps/api/Makefile and apps/mobile scripts.
.PHONY: api-gen api-build api-test api-lint api-run api-contract-test db-up db-down db-reset migrate migrate-down \
        mobile-typecheck mobile-lint mobile-test mobile-gen-api mobile-mock mobile-android mobile-ios mobile-contract-test

api-gen:
	$(MAKE) -C apps/api gen
api-build:
	$(MAKE) -C apps/api build
api-test:
	$(MAKE) -C apps/api test
api-lint:
	$(MAKE) -C apps/api lint
api-run:
	$(MAKE) -C apps/api run
api-contract-test:
	$(MAKE) -C apps/api contract-test

db-up:
	docker compose up -d --wait postgres
db-down:
	docker compose down
db-reset:
	docker compose down -v

migrate:
	$(MAKE) -C apps/api migrate
migrate-down:
	$(MAKE) -C apps/api migrate-down

mobile-typecheck:
	pnpm --filter mobile typecheck
mobile-lint:
	pnpm --filter mobile lint
mobile-test:
	pnpm --filter mobile test
mobile-gen-api:
	pnpm --filter mobile gen:api
mobile-mock:
	pnpm --filter mobile mock
mobile-android:
	pnpm --filter mobile android
mobile-ios:
	pnpm --filter mobile ios
mobile-contract-test:
	pnpm --filter mobile contract-test
