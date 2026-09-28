GO ?= go

.PHONY: test check integration

test:
	$(GO) test ./...

check: test
	$(GO) vet ./...

integration:
	GO="$(GO)" ./scripts/test-mysql.sh
