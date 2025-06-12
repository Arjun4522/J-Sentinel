# Makefile for Vulnerability Scanner

# Variables
BINARY_NAME=detect
MAIN_FILE=main.go
BUILD_DIR=build
VERSION=1.0.0
BUILD_TIME=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Build flags
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)"

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Default target
.PHONY: all
all: deps build

# Install dependencies
.PHONY: deps
deps:
	@echo "Installing dependencies..."
	$(GOGET) github.com/google/uuid@latest
	$(GOGET) gopkg.in/yaml.v3@latest
	$(GOMOD) tidy

# Build for current platform
.PHONY: build
build: deps
	@echo "Building $(BINARY_NAME)..."
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) $(MAIN_FILE)
	@echo "Build completed: ./$(BINARY_NAME)"

# Build for all platforms
.PHONY: build-all
build-all: deps
	@echo "Building for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	
	# Linux AMD64
	@echo "Building for Linux AMD64..."
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(MAIN_FILE)
	
	# Linux ARM64
	@echo "Building for Linux ARM64..."
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(MAIN_FILE)
	
	# macOS AMD64
	@echo "Building for macOS AMD64..."
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(MAIN_FILE)
	
	# macOS ARM64 (Apple Silicon)
	@echo "Building for macOS ARM64..."
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(MAIN_FILE)
	
	# Windows AMD64
	@echo "Building for Windows AMD64..."
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(MAIN_FILE)
	
	@echo "Cross-platform build completed in $(BUILD_DIR)/"

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -rf $(BUILD_DIR)

# Setup development environment
.PHONY: setup
setup: deps
	@echo "Setting up development environment..."
	@mkdir -p rules/python rules/java rules/javascript rules/cpp rules/csharp
	@echo "Development environment setup completed"

# Install the binary to system PATH
.PHONY: install
install: build
	@echo "Installing $(BINARY_NAME) to /usr/local/bin..."
	@sudo cp $(BINARY_NAME) /usr/local/bin/
	@echo "Installation completed"

# Uninstall the binary from system PATH
.PHONY: uninstall
uninstall:
	@echo "Uninstalling $(BINARY_NAME) from /usr/local/bin..."
	@sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "Uninstallation completed"

# Run the scanner with default settings
.PHONY: run
run: build
	@echo "Running vulnerability scanner..."
	./$(BINARY_NAME) --help

# Format Go code
.PHONY: fmt
fmt:
	@echo "Formatting Go code..."
	$(GOCMD) fmt ./...

# Lint Go code (requires golangci-lint)
.PHONY: lint
lint:
	@echo "Linting Go code..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found. Install it with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

# Run vulnerability scanner on itself
.PHONY: self-scan
self-scan: build
	@echo "Running vulnerability scanner on itself..."
	./$(BINARY_NAME) --source=. --verbose

# Create release
.PHONY: release
release: clean build-all
	@echo "Creating release archives..."
	@mkdir -p $(BUILD_DIR)/release
	
	# Create tar.gz for Unix systems
	@for binary in $(BUILD_DIR)/$(BINARY_NAME)-linux-* $(BUILD_DIR)/$(BINARY_NAME)-darwin-*; do \
		if [ -f "$$binary" ]; then \
			basename=$$(basename $$binary); \
			echo "Creating $$basename.tar.gz..."; \
			tar -czf $(BUILD_DIR)/release/$$basename.tar.gz -C $(BUILD_DIR) $$basename; \
		fi; \
	done
	
	# Create zip for Windows
	@for binary in $(BUILD_DIR)/$(BINARY_NAME)-windows-*.exe; do \
		if [ -f "$$binary" ]; then \
			basename=$$(basename $$binary .exe); \
			echo "Creating $$basename.zip..."; \
			cd $(BUILD_DIR) && zip release/$$basename.zip $$(basename $$binary) && cd ..; \
		fi; \
	done
	
	@echo "Release archives created in $(BUILD_DIR)/release/"

# Show help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all         - Install dependencies and build for current platform"
	@echo "  build       - Build for current platform"
	@echo "  build-all   - Build for all supported platforms"
	@echo "  deps        - Install Go dependencies"
	@echo "  test        - Run tests"
	@echo "  clean       - Clean build artifacts"
	@echo "  setup       - Setup development environment"
	@echo "  install     - Install binary to system PATH"
	@echo "  uninstall   - Remove binary from system PATH"
	@echo "  run         - Build and run with --help"
	@echo "  fmt         - Format Go code"
	@echo "  lint        - Lint Go code (requires golangci-lint)"
	@echo "  self-scan   - Run vulnerability scanner on itself"
	@echo "  release     - Create release archives"
	@echo "  help        - Show this help message"

# Default help
.DEFAULT_GOAL := help