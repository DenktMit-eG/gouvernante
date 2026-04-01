.PHONY: all build test lint fmt fmt-check vet staticcheck clean cover demo setup help

BINARY   := gouvernante
CMD      := ./cmd/gouvernante/
DIST     := dist
LDFLAGS  := -s -w
GOBIN    := $(shell go env GOPATH 2>/dev/null)/bin

PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64

# Tool detection — check PATH and GOPATH/bin
tool-check = $(if $(shell command -v $(1) 2>/dev/null || test -x $(GOBIN)/$(1) && echo found),,$(1))
MISSING_TOOLS := $(call tool-check,gofumpt) $(call tool-check,goimports) $(call tool-check,golangci-lint) $(call tool-check,staticcheck)
MISSING_TOOLS := $(strip $(MISSING_TOOLS))

# Resolve tool paths (prefer PATH, fall back to GOPATH/bin)
resolve = $(shell command -v $(1) 2>/dev/null || echo $(GOBIN)/$(1))
GOFUMPT       := $(call resolve,gofumpt)
GOIMPORTS     := $(call resolve,goimports)
GOLANGCI_LINT := $(call resolve,golangci-lint)
STATICCHECK   := $(call resolve,staticcheck)

# --- Default target ---

all: ensure-tools fmt lint test build

# --- Tool management ---

.PHONY: ensure-tools check-go

check-go:
	@command -v go >/dev/null 2>&1 || { echo "error: go is not installed. Install from https://go.dev/dl/"; exit 1; }

ensure-tools: check-go
ifneq ($(MISSING_TOOLS),)
	@echo "Missing tools: $(MISSING_TOOLS)"
	@echo ""
	@read -p "Install them via 'go install'? [y/N] " ans; \
	if [ "$$ans" = "y" ] || [ "$$ans" = "Y" ]; then \
		$(MAKE) setup; \
	else \
		echo "Aborting. Run 'make setup' to install manually."; \
		exit 1; \
	fi
endif

setup: check-go
	go install mvdan.cc/gofumpt@latest
	go install golang.org/x/tools/cmd/goimports@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	@echo ""
	@echo "All tools installed in $$(go env GOPATH)/bin."
	@echo "Ensure this directory is in your PATH."

# --- Build ---

build: check-go
	@mkdir -p $(DIST)/binaries
	@$(foreach platform,$(PLATFORMS),\
		$(eval OS := $(word 1,$(subst /, ,$(platform))))\
		$(eval ARCH := $(word 2,$(subst /, ,$(platform))))\
		$(eval EXT := $(if $(filter windows,$(OS)),.exe,))\
		echo "Building $(OS)/$(ARCH)..." && \
		GOOS=$(OS) GOARCH=$(ARCH) go build -trimpath -ldflags="$(LDFLAGS)" \
			-o $(DIST)/binaries/$(BINARY)-$(OS)-$(ARCH)$(EXT) $(CMD) && \
	) true
	@echo ""
	@echo "Binaries in $(DIST)/binaries/:"
	@ls -lh $(DIST)/binaries/

# --- Test ---

test: check-go
	go test -race -count=1 ./...

cover: check-go
	@mkdir -p $(DIST)/reports
	go test -race -coverprofile=$(DIST)/reports/coverage.out -covermode=atomic ./...
	go tool cover -func=$(DIST)/reports/coverage.out
	go tool cover -html=$(DIST)/reports/coverage.out -o $(DIST)/reports/coverage.html
	@echo ""
	@echo "Coverage report: $(DIST)/reports/coverage.html"

# --- Formatting ---

fmt: ensure-tools
	$(GOFUMPT) -w .
	$(GOIMPORTS) -w .

fmt-check: ensure-tools
	@test -z "$$($(GOFUMPT) -d .)" || (echo "code is not formatted; run 'make fmt'" && $(GOFUMPT) -d . && exit 1)
	@test -z "$$($(GOIMPORTS) -d .)" || (echo "imports are not organized; run 'make fmt'" && $(GOIMPORTS) -d . && exit 1)

# --- Linting ---

vet: check-go
	go vet ./...

staticcheck: ensure-tools
	$(STATICCHECK) ./...

lint: ensure-tools vet
	$(GOLANGCI_LINT) run ./...

# --- Utilities ---

clean:
	rm -rf $(DIST)
	rm -f scan-report-*.txt

demo: build
	./$(DIST)/binaries/$(BINARY)-$$(go env GOOS)-$$(go env GOARCH) -rules ./testdata/rules/incidents -dir ./testdata -host; \
	EXIT=$$?; \
	if [ $$EXIT -eq 2 ]; then echo "\nDemo complete: findings detected (expected)."; \
	elif [ $$EXIT -eq 0 ]; then echo "\nDemo complete: no findings."; \
	else exit $$EXIT; fi

help:
	@echo "Available targets:"
	@echo "  all            - Format, lint, test, and build (default)"
	@echo "  build          - Cross-compile for all platforms (output in dist/binaries/)"
	@echo "  test           - Run all tests with race detector"
	@echo "  cover          - Run tests with coverage (output in dist/reports/)"
	@echo "  fmt            - Format code with gofumpt and goimports"
	@echo "  fmt-check      - Check formatting without modifying files"
	@echo "  vet            - Run go vet"
	@echo "  staticcheck    - Run staticcheck"
	@echo "  lint           - Run golangci-lint (includes vet)"
	@echo "  setup          - Install all development tools"
	@echo "  clean          - Remove all build artifacts"
	@echo "  demo           - Build and run a demo scan"
	@echo "  help           - Show this help"
