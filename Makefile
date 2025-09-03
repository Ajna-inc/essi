ASKAR_NATIVE := $(shell go list -f '{{.Dir}}' github.com/Ajna-inc/askar-go)/native
CGO_RPATH := -Wl,-rpath,@executable_path -Wl,-rpath,@executable_path/native

.PHONY: test test-pkg build create-oob create-oob-invitation run-create-oob prepare-askar kanon-test run

test:
	go test ./...

# Usage: make test-pkg PKG=./pkg/didcomm/transport -run TestName -v
test-pkg:
	go test $(PKG) $(ARGS)

prepare-askar:
	@mkdir -p native
	@cp -f "$(ASKAR_NATIVE)/libaries_askar.dylib" native/ 2>/dev/null || true
	@command -v install_name_tool >/dev/null 2>&1 && \
		install_name_tool -id @rpath/libaries_askar.dylib native/libaries_askar.dylib || true

build: prepare-askar
	CGO_LDFLAGS="$(CGO_RPATH)" go build ./...

kanon-test: prepare-askar
	CGO_LDFLAGS="$(CGO_RPATH)" go build -tags "evm" -o kanon-test ./cmd/kanon-test
	@command -v install_name_tool >/dev/null 2>&1 && \
		install_name_tool -add_rpath @executable_path kanon-test || true
	@command -v install_name_tool >/dev/null 2>&1 && \
		install_name_tool -add_rpath @executable_path/native kanon-test || true

run: kanon-test
	./kanon-test $(ARGS)

create-oob: prepare-askar
	cd cmd/create-oob-invitation && CGO_LDFLAGS="$(CGO_RPATH)" go build -o create-oob-invitation .
	@command -v install_name_tool >/dev/null 2>&1 && \
		install_name_tool -add_rpath @executable_path cmd/create-oob-invitation/create-oob-invitation || true
	@command -v install_name_tool >/dev/null 2>&1 && \
		install_name_tool -add_rpath @executable_path/../../native cmd/create-oob-invitation/create-oob-invitation || true

# Alias target for convenience
create-oob-invitation: create-oob

run-create-oob: create-oob
	cd cmd/create-oob-invitation && ./create-oob-invitation $(ARGS)

.PHONY: help build test clean lint format deps

# Default target
help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@egrep '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build the project
	@echo "Building Essi-Go..."
	CGO_LDFLAGS="$(CGO_RPATH)" go build -v ./...

test: prepare-askar ## Run tests (exclude cmd packages)
	@echo "Running tests..."
	@PKGS=$$(go list ./... | grep -v '^github.com/ajna-inc/essi/cmd'); \
	DYLD_LIBRARY_PATH="$(PWD)/native:$$DYLD_LIBRARY_PATH" CGO_LDFLAGS="$(CGO_RPATH)" go test -v -race -coverprofile=coverage.out $$PKGS

test-coverage: test ## Run tests with coverage report
	@echo "Generating coverage report..."
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

clean: ## Clean build artifacts
	@echo "Cleaning..."
	go clean ./...
	rm -f coverage.out coverage.html kanon-test

lint: ## Run linter
	@echo "Running linter..."
	golangci-lint run ./...

format: ## Format code
	@echo "Formatting code..."
	go fmt ./...
	goimports -w .

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

deps-update: ## Update dependencies
	@echo "Updating dependencies..."
	go get -u ./...
	go mod tidy

install-tools: ## Install development tools
	@echo "Installing development tools..."
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

check-types: build ## Check types by building

validate: format lint test ## Run validation checks (format, lint, test)

dev-setup: install-tools deps ## Setup development environment

.DEFAULT_GOAL := help 