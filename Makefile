# Default is to run help target
.DEFAULT_GOAL := help

.PHONY: check
check: ## Run every check CI runs: formatting, vet, and tests with the race detector
	@test -z "$$(gofmt -l .)" || { gofmt -d .; exit 1; }
	@go vet ./...
	@go test -race ./...

.PHONY: test
test: ## Run tests
	@go test -v ./...

.PHONY: test-live
test-live: ## Run tests, including those that query public DoH resolvers
	@DOH_LIVE_TESTS=1 go test -v ./...

FUZZTIME ?= 10s

.PHONY: fuzz
fuzz: ## Run every fuzz target for FUZZTIME (default 10s) each
	@for pkg in $$(go list ./...); do \
		for target in $$(go test -list '^Fuzz' "$$pkg" | grep '^Fuzz'); do \
			echo "fuzzing $$target in $$pkg for $(FUZZTIME)"; \
			go test -run '^$$' -fuzz "^$$target\$$" -fuzztime $(FUZZTIME) "$$pkg" || exit 1; \
		done; \
	done

.PHONY: build
build: ## Build binary
	@go build -o doh

.PHONY: dist
dist: ## Build release archives for every platform into dist/, reproducibly
	@./scripts/build-release.sh

.PHONY: help
help: ## Print this help message
	@cat Makefile | grep -E '^[a-zA-Z_-]+:.*?## .*$$' | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
