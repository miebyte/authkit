GO ?= go
NPM ?= npm

.PHONY: test check integration admin-ui

test:
	$(GO) test ./...

check: test
	$(GO) vet ./...

integration:
	GO="$(GO)" ./scripts/test-mysql.sh

admin-ui:
	$(NPM) --prefix admin/frontend ci
	$(NPM) --prefix admin/frontend run build
