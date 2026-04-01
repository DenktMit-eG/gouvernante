.PHONY: all build test lint fmt fmt-check vet staticcheck clean cover scan demo setup test-integration help

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

# Colours (disabled if not a terminal)
BOLD    := $(shell tput bold 2>/dev/null)
GREEN   := $(shell tput setaf 2 2>/dev/null)
CYAN    := $(shell tput setaf 6 2>/dev/null)
YELLOW  := $(shell tput setaf 3 2>/dev/null)
RESET   := $(shell tput sgr0 2>/dev/null)

define STEP
	@echo ""
	@echo "$(BOLD)$(CYAN)══════════════════════════════════════════════════$(RESET)"
	@echo "$(BOLD)$(CYAN)  $(1)$(RESET)"
	@echo "$(BOLD)$(CYAN)══════════════════════════════════════════════════$(RESET)"
	@echo ""
endef

define PASS
	@echo ""
	@echo "$(BOLD)$(GREEN)  ✔ $(1)$(RESET)"
	@echo ""
endef

# --- Default target ---

all: ensure-tools fmt lint cover build test-integration
	$(call PASS,All checks passed.)

# --- Tool management ---

.PHONY: ensure-tools check-go

check-go:
	@command -v go >/dev/null 2>&1 || { echo "error: go is not installed. Install from https://go.dev/dl/"; exit 1; }

ensure-tools: check-go
ifneq ($(MISSING_TOOLS),)
	@echo "$(YELLOW)Missing tools: $(MISSING_TOOLS)$(RESET)"
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
	$(call STEP,Installing development tools)
	go install mvdan.cc/gofumpt@latest
	go install golang.org/x/tools/cmd/goimports@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	$(call PASS,All tools installed in $$(go env GOPATH)/bin)

# --- Build ---

build: check-go
	$(call STEP,Building binaries)
	@mkdir -p $(DIST)/binaries
	@$(foreach platform,$(PLATFORMS),\
		$(eval OS := $(word 1,$(subst /, ,$(platform))))\
		$(eval ARCH := $(word 2,$(subst /, ,$(platform))))\
		$(eval EXT := $(if $(filter windows,$(OS)),.exe,))\
		echo "  $(OS)/$(ARCH)" && \
		GOOS=$(OS) GOARCH=$(ARCH) go build -trimpath -ldflags="$(LDFLAGS)" \
			-o $(DIST)/binaries/$(BINARY)-$(OS)-$(ARCH)$(EXT) $(CMD) && \
	) true
	$(call PASS,Binaries in $(DIST)/binaries/)

# --- Test ---

test: check-go
	$(call STEP,Running tests)
	go test -race -count=1 ./...
	$(call PASS,All tests passed)

cover: check-go
	$(call STEP,Running tests with coverage)
	@mkdir -p $(DIST)/reports
	go test -race -coverprofile=$(DIST)/reports/coverage.out -covermode=atomic ./...
	go tool cover -func=$(DIST)/reports/coverage.out
	go tool cover -html=$(DIST)/reports/coverage.out -o $(DIST)/reports/coverage.html
	$(call PASS,Coverage report: $(DIST)/reports/coverage.html)

scan: build
	$(call STEP,Running scan on test fixtures)
	@mkdir -p $(DIST)/reports
	@./$(DIST)/binaries/$(BINARY)-$$(go env GOOS)-$$(go env GOARCH) \
		-rules ./testdata/rules/incidents \
		-dir ./testdata \
		-recursive \
		-host \
		-output $(DIST)/reports/scan-report.txt || true
	@./$(DIST)/binaries/$(BINARY)-$$(go env GOOS)-$$(go env GOARCH) \
		-rules ./testdata/rules/incidents \
		-dir ./testdata \
		-recursive \
		-host \
		-json \
		-output $(DIST)/reports/scan-report.json || true
	$(call PASS,Scan reports in $(DIST)/reports/)

# --- Formatting ---

fmt: ensure-tools
	$(call STEP,Formatting code)
	$(GOFUMPT) -w .
	$(GOIMPORTS) -w .
	$(call PASS,Code formatted)

fmt-check: ensure-tools
	$(call STEP,Checking code format)
	@test -z "$$($(GOFUMPT) -d .)" || (echo "code is not formatted; run 'make fmt'" && $(GOFUMPT) -d . && exit 1)
	@test -z "$$($(GOIMPORTS) -d .)" || (echo "imports are not organized; run 'make fmt'" && $(GOIMPORTS) -d . && exit 1)
	$(call PASS,Format OK)

# --- Linting ---

vet: check-go
	go vet ./...

staticcheck: ensure-tools
	$(STATICCHECK) ./...

lint: ensure-tools vet
	$(call STEP,Linting)
	$(GOLANGCI_LINT) run ./...
	$(call PASS,Lint clean)

# --- Integration test ---

test-integration:
	$(call STEP,Running integration tests (Docker))
	docker build -f Dockerfile.integration -t gouvernante-test .
	docker run --rm gouvernante-test
	$(call PASS,Integration tests passed)

# --- Utilities ---

clean:
	rm -rf $(DIST)
	rm -f scan-report-*.txt

demo: build
	$(call STEP,Running demo scan)
	./$(DIST)/binaries/$(BINARY)-$$(go env GOOS)-$$(go env GOARCH) -rules ./testdata/rules/incidents -dir ./testdata -host; \
	EXIT=$$?; \
	if [ $$EXIT -eq 2 ]; then echo "\nDemo complete: findings detected (expected)."; \
	elif [ $$EXIT -eq 0 ]; then echo "\nDemo complete: no findings."; \
	else exit $$EXIT; fi

help:
	@echo "$(BOLD)Available targets:$(RESET)"
	@echo "  $(CYAN)all$(RESET)              Format, lint, test, build, and integration test (default)"
	@echo "  $(CYAN)build$(RESET)            Cross-compile for all platforms (output in dist/binaries/)"
	@echo "  $(CYAN)test$(RESET)             Run all tests with race detector"
	@echo "  $(CYAN)cover$(RESET)            Run tests with coverage (output in dist/reports/)"
	@echo "  $(CYAN)fmt$(RESET)              Format code with gofumpt and goimports"
	@echo "  $(CYAN)fmt-check$(RESET)        Check formatting without modifying files"
	@echo "  $(CYAN)vet$(RESET)              Run go vet"
	@echo "  $(CYAN)staticcheck$(RESET)      Run staticcheck"
	@echo "  $(CYAN)lint$(RESET)             Run golangci-lint (includes vet)"
	@echo "  $(CYAN)setup$(RESET)            Install all development tools"
	@echo "  $(CYAN)scan$(RESET)             Run scan on test fixtures (reports in dist/reports/)"
	@echo "  $(CYAN)test-integration$(RESET) Run Docker integration test (IOCs + node_modules)"
	@echo "  $(CYAN)clean$(RESET)            Remove all build artifacts"
	@echo "  $(CYAN)demo$(RESET)             Build and run a demo scan"
	@echo "  $(CYAN)help$(RESET)             Show this help"
