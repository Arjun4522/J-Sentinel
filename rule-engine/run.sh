#!/bin/bash

# OWASP Vulnerability Detector Runner Script
# This script runs the Python-based rule engine for vulnerability detection

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PYTHON_SCRIPT="detect.py"
DEFAULT_INPUT="output"
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

# Function to check if Python is installed
check_python() {
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
        print_success "Python found: $PYTHON_VERSION"
    else
        print_error "Python3 not found. Please install Python 3.6 or higher."
        exit 1
    fi
}

# Function to check Python dependencies
check_dependencies() {
    print_status "Checking Python dependencies..."
    if python3 -c "import yaml" 2>/dev/null; then
        print_success "PyYAML is installed"
    else
        print_status "Installing PyYAML..."
        pip3 install pyyaml
        print_success "PyYAML installed"
    fi
}

# Function to run the detector
run_detector() {
    local input_folder="${1:-$DEFAULT_INPUT}"
    local output_file="${2:-$DEFAULT_OUTPUT}"
    
    print_status "Running OWASP Vulnerability Detector..."
    print_status "Input folder: $input_folder"
    print_status "Output file: $output_file"
    
    if [ ! -d "$input_folder" ]; then
        print_error "Input folder '$input_folder' not found!"
        print_status "Please provide the output folder containing JSON graph data."
        exit 1
    fi
    
    # Check for rules.yaml
    if [ ! -f "rules.yaml" ]; then
        print_error "rules.yaml not found in current directory!"
        exit 1
    fi
    
    # Run the detector
    if python3 "$PYTHON_SCRIPT" "$input_folder" "$output_file"; then
        print_success "Analysis completed successfully!"
        print_status "Results saved to: $output_file"
        
        # Show file sizes
        OUTPUT_SIZE=$(du -h "$output_file" | cut -f1)
        print_status "Output size: $OUTPUT_SIZE"
        
    else
        print_error "Analysis failed. Please check the error messages above."
        exit 1
    fi
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS] [INPUT_FOLDER] [OUTPUT_FILE]"
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo ""
    echo "Arguments:"
    echo "  INPUT_FOLDER            Folder containing JSON graph data (default: $DEFAULT_INPUT)"
    echo "  OUTPUT_FILE             Output vulnerability report (default: $DEFAULT_OUTPUT)"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Use default folder and output"
    echo "  $0 output my_report.json             # Use custom folder and output"
}

# Main execution
main() {
    local input_folder=""
    local output_file=""
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -*)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
            *)
                if [ -z "$input_folder" ]; then
                    input_folder="$1"
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
    input_folder="${input_folder:-$DEFAULT_INPUT}"
    output_file="${output_file:-$DEFAULT_OUTPUT}"
    
    # Print banner
    echo -e "${BLUE}"
    echo "🛡️  OWASP Vulnerability Detector"
    echo "================================="
    echo -e "${NC}"
    
    # Check prerequisites
    check_python
    check_dependencies
    
    # Execute
    run_detector "$input_folder" "$output_file"
    
    print_success "Done!"
}

# Run main function
main "$@"