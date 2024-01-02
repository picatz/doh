# Default is to run help target
.DEFAULT_GOAL := help

# VERSION := $(shell git describe --tags --always --dirty)
# BUILD := $(shell git rev-parse HEAD)
# PROJECTNAME := $(shell basename "$(PWD)")

.PHONY: test
test: ## Run tests
	@go test -v ./...

.PHONY: build
build: ## Build binary
	@go build -o doh

.PHONY: help
help: ## Print this help message
	@cat Makefile | grep -E '^[a-zA-Z_-]+:.*?## .*$$' | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
