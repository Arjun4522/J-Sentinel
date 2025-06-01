#!/bin/bash

# OWASP Vulnerability Detector Runner Script
# This script compiles and runs the OWASP vulnerability detector

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
JAVA_FILE="OwaspVulnerabilityDetector.java"
CLASS_NAME="OwaspVulnerabilityDetector"
DEFAULT_INPUT="taint_analysis.json"
DEFAULT_OUTPUT="owasp_vulnerabilities.json"

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

# Function to check if Java is installed
check_java() {
    if command -v java &> /dev/null && command -v javac &> /dev/null; then
        JAVA_VERSION=$(java -version 2>&1 | head -n1 | cut -d'"' -f2)
        print_success "Java found: $JAVA_VERSION"
    else
        print_error "Java not found. Please install Java 8 or higher."
        exit 1
    fi
}

# Function to check classpath
check_classpath() {
    if [ -z "$CLASSPATH" ]; then
        print_warning "CLASSPATH not set. Setting basic classpath..."
        export CLASSPATH=".:$HOME/.m2/repository/org/json/json/20240303/json-20240303.jar"
    fi
    print_status "Using CLASSPATH: $CLASSPATH"
}

# Function to compile Java code
compile_detector() {
    print_status "Compiling $JAVA_FILE..."
    
    if javac -cp "$CLASSPATH" "$JAVA_FILE" 2>/dev/null; then
        print_success "Compilation successful"
    else
        print_error "Compilation failed. Trying with downloaded JSON library..."
        
        # Download JSON library if not present
        JSON_JAR="json-20240303.jar"
        if [ ! -f "$JSON_JAR" ]; then
            print_status "Downloading JSON library..."
            curl -L -o "$JSON_JAR" "https://repo1.maven.org/maven2/org/json/json/20240303/json-20240303.jar"
        fi
        
        # Retry compilation with downloaded JAR
        if javac -cp ".:$JSON_JAR" "$JAVA_FILE"; then
            export CLASSPATH=".:$JSON_JAR"
            print_success "Compilation successful with downloaded library"
        else
            print_error "Compilation failed. Please check your Java code."
            exit 1
        fi
    fi
}

# Function to run the detector
run_detector() {
    local input_file="${1:-$DEFAULT_INPUT}"
    local output_file="${2:-$DEFAULT_OUTPUT}"
    
    print_status "Running OWASP Vulnerability Detector..."
    print_status "Input file: $input_file"
    print_status "Output file: $output_file"
    
    if [ ! -f "$input_file" ]; then
        print_error "Input file '$input_file' not found!"
        print_status "Please provide the taint analysis JSON file."
        exit 1
    fi
    
    # Run the detector
    if java -cp "$CLASSPATH" "$CLASS_NAME" "$input_file" "$output_file"; then
        print_success "Analysis completed successfully!"
        print_status "Results saved to: $output_file"
        
        # Show file sizes
        INPUT_SIZE=$(du -h "$input_file" | cut -f1)
        OUTPUT_SIZE=$(du -h "$output_file" | cut -f1)
        print_status "Input size: $INPUT_SIZE, Output size: $OUTPUT_SIZE"
        
    else
        print_error "Analysis failed. Please check the error messages above."
        exit 1
    fi
}

# Function to create sample taint analysis file
create_sample_input() {
    print_status "Creating sample taint analysis file..."
    
    cat > "$DEFAULT_INPUT" << 'EOF'
{
  "scanId": "sample-scan-001",
  "taintedPaths": [
    {
      "pathNodes": [
        {
          "name": "userInput",
          "id": 1,
          "type": "PARAMETER"
        },
        {
          "scope": "logger",
          "name": "info",
          "id": 2,
          "type": "METHOD_CALL"
        }
      ],
      "sourceId": 1,
      "severity": "HIGH",
      "sinkId": 2,
      "sourceName": "userInput",
      "vulnerability": "Potential taint flow from userInput to info",
      "sinkName": "info"
    },
    {
      "pathNodes": [
        {
          "name": "password",
          "id": 3,
          "type": "PARAMETER"
        },
        {
          "scope": "logger",
          "name": "debug",
          "id": 4,
          "type": "METHOD_CALL"
        }
      ],
      "sourceId": 3,
      "severity": "HIGH",
      "sinkId": 4,
      "sourceName": "password",
      "vulnerability": "Potential taint flow from password to debug",
      "sinkName": "debug"
    }
  ],
  "timestamp": 1748809181932
}
EOF
    
    print_success "Sample input created: $DEFAULT_INPUT"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS] [INPUT_FILE] [OUTPUT_FILE]"
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  -s, --sample            Create sample input file"
    echo "  -c, --compile-only      Only compile, don't run"
    echo "  -r, --run-only          Only run (skip compilation)"
    echo "  --clean                 Clean compiled files"
    echo ""
    echo "Arguments:"
    echo "  INPUT_FILE              Taint analysis JSON file (default: $DEFAULT_INPUT)"
    echo "  OUTPUT_FILE             Output vulnerability report (default: $DEFAULT_OUTPUT)"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Use default files"
    echo "  $0 my_taint.json my_report.json      # Use custom files"
    echo "  $0 --sample                          # Create sample input"
    echo "  $0 --compile-only                    # Just compile"
}

# Function to clean compiled files
clean_files() {
    print_status "Cleaning compiled files..."
    rm -f *.class
    print_success "Cleaned compiled files"
}

# Main execution
main() {
    local compile_only=false
    local run_only=false
    local input_file=""
    local output_file=""
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -s|--sample)
                create_sample_input
                exit 0
                ;;
            -c|--compile-only)
                compile_only=true
                shift
                ;;
            -r|--run-only)
                run_only=true
                shift
                ;;
            --clean)
                clean_files
                exit 0
                ;;
            -*)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
            *)
                if [ -z "$input_file" ]; then
                    input_file="$1"
                elif [ -z "$output_file" ]; then
                    output_file="$1"
                else
                    print_error "Too many arguments"
                    show_usage
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    # Set defaults if not provided
    input_file="${input_file:-$DEFAULT_INPUT}"
    output_file="${output_file:-$DEFAULT_OUTPUT}"
    
    # Print banner
    echo -e "${BLUE}"
    echo "🛡️  OWASP Vulnerability Detector"
    echo "================================="
    echo -e "${NC}"
    
    # Check prerequisites
    check_java
    check_classpath
    
    # Execute based on options
    if [ "$run_only" = false ]; then
        compile_detector
    fi
    
    if [ "$compile_only" = false ]; then
        run_detector "$input_file" "$output_file"
    fi
    
    print_success "Done!"
}

# Run main function
main "$@"