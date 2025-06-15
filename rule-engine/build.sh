#!/bin/bash

# Vulnerability Scanner Build Script
# This script builds the Go vulnerability scanner with proper dependencies

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Go is installed
check_go_installation() {
    print_status "Checking Go installation..."
    
    if ! command -v go &> /dev/null; then
        print_error "Go is not installed. Please install Go 1.19 or later."
        echo "Visit: https://golang.org/doc/install"
        exit 1
    fi
    
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    print_success "Go version $GO_VERSION found"
    
    # Check if Go version is 1.19 or later
    if [[ $(echo "$GO_VERSION 1.19" | tr " " "\n" | sort -V | head -n1) != "1.19" ]]; then
        print_warning "Go version $GO_VERSION detected. Recommended: 1.19 or later"
    fi
}

# Initialize Go module if needed
init_go_module() {
    print_status "Initializing Go module..."
    
    if [ ! -f "go.mod" ]; then
        print_status "Creating go.mod file..."
        go mod init detect
        print_success "Go module initialized"
    else
        print_status "Go module already exists"
    fi
}

# Install dependencies
install_dependencies() {
    print_status "Installing Go dependencies..."
    
    go get github.com/google/uuid@v1.6.0
    go get gopkg.in/yaml.v3@v3.0.1
    go get github.com/mattn/go-sqlite3@v1.14.28
    
    if [ $? -eq 0 ]; then
        print_success "Dependencies installed"
    else
        print_error "Failed to install dependencies"
        exit 1
    fi
    
    print_status "Tidying up Go module..."
    go mod tidy
    if [ $? -eq 0 ]; then
        print_success "Module tidied"
    else
        print_error "Failed to tidy module"
        exit 1
    fi
}
# Build the database initializer
build_initdb() {
    print_status "Building database initializer..."
    
    go build -o initdb initdb.go
    
    if [ $? -eq 0 ]; then
        print_success "Database initializer built: ./initdb"
    else
        print_error "Failed to build initdb"
        exit 1
    fi
}

# Build the main application
build_application() {
    print_status "Building vulnerability scanner..."
    
    # Get build information
    BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    VERSION="1.0.0"
    
    # Build flags
    LDFLAGS="-X main.Version=$VERSION -X main.BuildTime=$BUILD_TIME -X main.GitCommit=$GIT_COMMIT"
    
    # Build for current platform
    print_status "Building for current platform ($(go env GOOS)/$(go env GOARCH))..."
    go build -ldflags "$LDFLAGS" -o detect main.go db_setup.go
    
    if [ $? -eq 0 ]; then
        print_success "Build completed successfully"
        print_success "Executable: ./detect"
    else
        print_error "Build failed"
        exit 1
    fi
}

# Build for multiple platforms
build_cross_platform() {
    print_status "Building for multiple platforms..."
    
    BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    VERSION="1.0.0"
    LDFLAGS="-X main.Version=$VERSION -X main.BuildTime=$BUILD_TIME -X main.GitCommit=$GIT_COMMIT"
    
    # Create build directory
    mkdir -p build
    
    # Define platforms
    platforms=(
        "linux/amd64"
        "linux/arm64"
        "darwin/amd64"
        "darwin/arm64"
        "windows/amd64"
    )
    
    for platform in "${platforms[@]}"; do
        IFS='/' read -r -a platform_split <<< "$platform"
        GOOS="${platform_split[0]}"
        GOARCH="${platform_split[1]}"
        
        output_name="detect-$GOOS-$GOARCH"
        if [ "$GOOS" = "windows" ]; then
            output_name="$output_name.exe"
        fi
        
        print_status "Building for $GOOS/$GOARCH..."
        
        env GOOS="$GOOS" GOARCH="$GOARCH" go build -ldflags "$LDFLAGS" -o "build/$output_name" main.go db_setup.go
        
        if [ $? -eq 0 ]; then
            print_success "Built build/$output_name"
        else
            print_error "Failed to build for $GOOS/$GOARCH"
        fi
    done
}

# Create default configuration
create_default_config() {
    print_status "Creating default configuration..."
    
    cat > config.yaml << 'EOF'
# Vulnerability Scanner Configuration
source_dir: "."
rules_dir: "rules"
output_path: "vulnerability_report.json"
max_workers: 8
timeout: 300
use_semgrep_registry: false
verbose: false

# Additional settings
exclude_dirs:
  - node_modules
  - .git
  - __pycache__
  - venv
  - build
  - dist
  - target

# Language-specific settings
languages:
  python:
    extensions: [".py", ".py3", ".pyw"]
  java:
    extensions: [".java"]
  javascript:
    extensions: [".js", ".jsx", ".ts", ".tsx", ".mjs"]
  cpp:
    extensions: [".cpp", ".cc", ".cxx", ".c++", ".hpp", ".h", ".c"]
  csharp:
    extensions: [".cs"]
EOF
    
    print_success "Default configuration created: config.yaml"
}

# Create sample rules
create_sample_rules() {
    print_status "Creating sample rules..."
    
    mkdir -p rules/python rules/java rules/javascript
    
    # Python rules
    cat > rules/python/security.yaml << 'EOF'
rules:
  - id: py-sql-injection
    category: Security
    type: regex
    pattern: '(execute|cursor\.execute|query)\s*\(\s*["\'].*%.*["\']'
    severity: HIGH
    message: Potential SQL injection vulnerability
    fix: Use parameterized queries with ? placeholders
    cwe: CWE-89
    owasp: A03:2021
    confidence: HIGH
    tags: [sql-injection, security]
    
  - id: py-command-injection
    category: Security
    type: regex
    pattern: '(os\.system|subprocess\.call|subprocess\.run|os\.popen)\s*\([^)]*\+'
    severity: HIGH
    message: Potential command injection vulnerability
    fix: Use subprocess with shell=False and validate inputs
    cwe: CWE-78
    owasp: A03:2021
    confidence: HIGH
    tags: [command-injection, security]
    
  - id: py-hardcoded-secrets
    category: Security
    type: regex
    pattern: '(password|secret|key|token)\s*=\s*["\'][^"\']{8,}["\']'
    severity: MEDIUM
    message: Potential hardcoded secret detected
    fix: Use environment variables or secure configuration
    cwe: CWE-798
    owasp: A02:2021
    confidence: MEDIUM
    tags: [secrets, hardcoded-credentials]
EOF

    # Java rules
    cat > rules/java/security.yaml << 'EOF'
rules:
  - id: java-sql-injection
    category: Security
    type: regex
    pattern: '(executeQuery|executeUpdate|execute)\s*\(\s*["\'].*\+'
    severity: HIGH
    message: Potential SQL injection vulnerability
    fix: Use PreparedStatement with parameter binding
    cwe: CWE-89
    owasp: A03:2021
    confidence: HIGH
    tags: [sql-injection, security]
    
  - id: java-deserialization
    category: Security
    type: regex
    pattern: '(ObjectInputStream|readObject|readUnshared)\s*\('
    severity: HIGH
    message: Potential deserialization vulnerability
    fix: Validate and sanitize serialized data
    cwe: CWE-502
    owasp: A08:2021
    confidence: MEDIUM
    tags: [deserialization, security]
EOF

    # JavaScript rules
    cat > rules/javascript/security.yaml << 'EOF'
rules:
  - id: js-xss
    category: Security
    type: regex
    pattern: '(innerHTML|outerHTML|document\.write)\s*=.*\+'
    severity: MEDIUM
    message: Potential XSS vulnerability
    fix: Sanitize user input before DOM insertion
    cwe: CWE-79
    owasp: A03:2021
    confidence: MEDIUM
    tags: [xss, security]
    
  - id: js-eval-usage
    category: Security
    type: regex
    pattern: '\beval\s*\('
    severity: HIGH
    message: Use of eval() function detected
    fix: Avoid eval() and use safer alternatives
    cwe: CWE-95
    owasp: A03:2021
    confidence: HIGH
    tags: [code-injection, security]
EOF
    
    print_success "Sample rules created in rules/ directory"
}

# Run tests
run_tests() {
    print_status "Running tests..."
    
    if ls *_test.go >/dev/null 2>&1; then
        go test -v ./...
        if [ $? -eq 0 ]; then
            print_success "All tests passed"
        else
            print_error "Some tests failed"
            exit 1
        fi
    else
        print_warning "No test files found"
    fi
}

# Check for Semgrep (optional)
check_semgrep() {
    print_status "Checking for Semgrep installation..."
    
    if command -v semgrep &> /dev/null; then
        SEMGREP_VERSION=$(semgrep --version)
        print_success "Semgrep found: $SEMGREP_VERSION"
    else
        print_warning "Semgrep not found. Install it for enhanced scanning capabilities:"
        echo "  pip install semgrep"
        echo "  or visit: https://semgrep.dev/docs/getting-started/"
    fi
}

# Display usage information
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -c, --cross         Build for multiple platforms"
    echo "  -t, --test          Run tests after building"
    echo "  -s, --setup         Create default configuration and rules"
    echo "  --clean             Clean build artifacts"
    echo ""
    echo "Examples:"
    echo "  $0                  # Build for current platform"
    echo "  $0 -c               # Build for multiple platforms"
    echo "  $0 -s               # Setup configuration and rules"
    echo "  $0 --clean          # Clean build artifacts"
}

# Clean build artifacts
clean_build() {
    print_status "Cleaning build artifacts..."
    
    rm -f detect
    rm -f initdb
    rm -rf build/
    rm -f go.sum
    
    print_success "Build artifacts cleaned"
}

# Main function
main() {
    local cross_build=false
    local run_tests_flag=false
    local setup_flag=false
    local clean_flag=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -c|--cross)
                cross_build=true
                shift
                ;;
            -t|--test)
                run_tests_flag=true
                shift
                ;;
            -s|--setup)
                setup_flag=true
                shift
                ;;
            --clean)
                clean_flag=true
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Clean if requested
    if [ "$clean_flag" = true ]; then
        clean_build
        exit 0
    fi
    
    print_status "Starting build process..."
    
    # Check prerequisites
    check_go_installation
    check_semgrep
    
    # Initialize and build
    init_go_module
    install_dependencies
    
    # Setup configuration and rules if requested
    if [ "$setup_flag" = true ]; then
        create_default_config
        create_sample_rules
        build_initdb
    fi
    
    # Run tests if requested
    if [ "$run_tests_flag" = true ]; then
        run_tests
    fi
    
    # Build application
    if [ "$cross_build" = true ]; then
        build_cross_platform
    else
        build_application
    fi
    
    print_success "Build process completed!"
    echo ""
    echo "Next steps:"
    echo "1. Run the scanner: ./detect --help"
    echo "2. Initialize the database (if needed): ./initdb"
    echo "3. Configure settings in config.yaml (if created)"
    echo "4. Add custom rules in the rules/ directory"
    echo "5. Consider installing Semgrep for enhanced scanning"
}

# Run main function with all arguments
main "$@"