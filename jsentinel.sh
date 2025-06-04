#!/bin/bash

# J-Sentinel CLI Agent
# Usage: ./jsentinel.sh <subcommand> [options]

# Constants
BASE_DIR="$(pwd)"
LIB_DIR="$BASE_DIR/lib"
OUTPUT_DIR="$BASE_DIR/output"
CLASSPATH="$LIB_DIR/*:$BASE_DIR"
API_USER="user"
API_PASSWORD="secret"
DEFAULT_ENDPOINT="http://localhost:8080/api"
SCANID_FILE="$BASE_DIR/.jsentinel_scanid"
DEFAULT_CODEGRAPH="$OUTPUT_DIR/scan.json"

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Format JSON file using jq or Python
format_json() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        echo "Error: Cannot format $file (file not found)"
        return 1
    fi
    if command -v jq &> /dev/null; then
        jq . "$file" > "$file.tmp" && mv "$file.tmp" "$file"
        if [[ $? -eq 0 ]]; then
            echo "Formatted JSON in $file using jq"
        else
            echo "Error: Failed to format $file with jq"
            return 1
        fi
    else
        python3 -c "import json; with open('$file', 'r') as f: data = json.load(f); with open('$file', 'w') as f: json.dump(data, f, indent=2)" 2>/dev/null
        if [[ $? -eq 0 ]]; then
            echo "Formatted JSON in $file using Python"
        else
            echo "Warning: Could not format $file (install jq or ensure Python is available)"
            return 1
        fi
    fi
}

# Help message
usage() {
    echo "J-Sentinel CLI Agent"
    echo "Usage: $0 <subcommand> [options]"
    echo ""
    echo "Subcommands:"
    echo "  scan        Scan code and generate code graph"
    echo "  taint       Perform taint analysis"
    echo "  cfg         Extract Control Flow Graph (CFG)"
    echo "  dfg         Extract Data Flow Graph (DFG)"
    echo ""
    echo "Options:"
    echo "  --input <path>       Input directory or file (default: test/)"
    echo "  --output <file>      Output JSON file (default: output/<subcommand>.json)"
    echo "  --endpoint <url>     API gateway endpoint (default: $DEFAULT_ENDPOINT)"
    echo "  --user <username>    API username (default: user)"
    echo "  --password <pass>    API password (default: secret)"
    echo "  --local              Run in local mode (no API)"
    echo "  --help               Show this help message"
    exit 1
}

# Compile Java files if needed
compile_java() {
    local java_file="$1"
    if [[ ! -f "${java_file%.java}.class" ]] || [[ "$java_file" -nt "${java_file%.java}.class" ]]; then
        echo "Compiling $java_file..."
        javac -cp "$CLASSPATH" "$java_file"
        if [[ $? -ne 0 ]]; then
            echo "Error: Compilation failed for $java_file"
            exit 1
        fi
    fi
}

# Extract scanId from JSON file
extract_scanid() {
    local json_file="$1"
    if [[ -f "$json_file" ]]; then
        if command -v jq &> /dev/null; then
            jq -r '.scanId' "$json_file" 2>/dev/null
        else
            grep -o '"scanId":"[^"]*"' "$json_file" | cut -d'"' -f4
        fi
    fi
}

# Parse arguments
SUBCOMMAND=""
INPUT_DIR="$BASE_DIR/test"
OUTPUT_FILE=""
ENDPOINT=""
LOCAL_MODE=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        scan|taint|cfg|dfg)
            SUBCOMMAND="$1"
            shift
            ;;
        --input)
            INPUT_DIR="$2"
            shift 2
            ;;
        --output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --endpoint)
            ENDPOINT="$2"
            shift 2
            ;;
        --user)
            API_USER="$2"
            shift 2
            ;;
        --password)
            API_PASSWORD="$2"
            shift 2
            ;;
        --local)
            LOCAL_MODE=true
            shift
            ;;
        --help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Validate subcommand
if [[ -z "$SUBCOMMAND" ]]; then
    echo "Error: Subcommand is required"
    usage
fi

# Set default output file
if [[ -z "$OUTPUT_FILE" ]]; then
    OUTPUT_FILE="$OUTPUT_DIR/${SUBCOMMAND}.json"
fi

# Execute subcommand
case "$SUBCOMMAND" in
    scan)
        JAVA_FILE="$BASE_DIR/scanner.java"
        if [[ ! -f "$JAVA_FILE" ]]; then
            echo "Error: scanner.java not found in $BASE_DIR"
            exit 1
        fi
        compile_java "$JAVA_FILE"
        echo "Running scanner with API endpoint ${ENDPOINT:-$DEFAULT_ENDPOINT}/scan..."
        OUTPUT=$(java -cp "$CLASSPATH" scanner "$INPUT_DIR" --endpoint "${ENDPOINT:-$DEFAULT_ENDPOINT}/scan" 2>&1)
        if [[ $? -eq 0 ]]; then
            SCAN_ID=$(echo "$OUTPUT" | grep -o 'scanId: [a-f0-9-]*' | cut -d' ' -f2)
            if [[ -n "$SCAN_ID" ]]; then
                echo "$SCAN_ID" > "$SCANID_FILE"
                echo "Scan ID: $SCAN_ID stored in $SCANID_FILE"
                curl -u "$API_USER:$API_PASSWORD" "${ENDPOINT:-$DEFAULT_ENDPOINT}/graph?scanId=$SCAN_ID" -o "$OUTPUT_FILE"
                format_json "$OUTPUT_FILE"
            else
                echo "Error: Could not extract scanId from scanner output"
                echo "$OUTPUT"
                exit 1
            fi
        else
            echo "Error: Scanner failed"
            echo "$OUTPUT"
            exit 1
        fi
        ;;
    taint|cfg|dfg)
        if [[ "$SUBCOMMAND" == "taint" ]]; then
            JAVA_FILE="$BASE_DIR/analyse.java"
            JAVA_CLASS="analyse"
            ENDPOINT_PATH="taint"
        elif [[ "$SUBCOMMAND" == "cfg" ]]; then
            JAVA_FILE="$BASE_DIR/cfg_extract.java"
            JAVA_CLASS="cfg_extract"
            ENDPOINT_PATH="cfg"
        else
            JAVA_FILE="$BASE_DIR/dfg_extract.java"
            JAVA_CLASS="dfg_extract"
            ENDPOINT_PATH="dfg"
        fi
        if [[ ! -f "$JAVA_FILE" ]]; then
            echo "Error: ${JAVA_FILE##*/} not found in $BASE_DIR"
            exit 1
        fi
        compile_java "$JAVA_FILE"
        if [[ "$LOCAL_MODE" == true ]]; then
            echo "Running $SUBCOMMAND locally using $DEFAULT_CODEGRAPH..."
            java -cp "$CLASSPATH" "$JAVA_CLASS" --local "$DEFAULT_CODEGRAPH" --output "$OUTPUT_FILE"
            format_json "$OUTPUT_FILE"
        else
            if [[ ! -f "$SCANID_FILE" ]]; then
                echo "Error: No scanId found. Run 'jsentinel scan' first."
                exit 1
            fi
            SCAN_ID=$(cat "$SCANID_FILE")
            if [[ -z "$SCAN_ID" ]]; then
                echo "Error: Invalid scanId in $SCANID_FILE"
                exit 1
            fi
            echo "Running $SUBCOMMAND via API for scanId $SCAN_ID..."
            curl -u "$API_USER:$API_PASSWORD" "${ENDPOINT:-$DEFAULT_ENDPOINT}/$ENDPOINT_PATH?scanId=$SCAN_ID" -o "$OUTPUT_FILE"
            format_json "$OUTPUT_FILE"
        fi
        ;;
esac

# Verify output
if [[ -f "$OUTPUT_FILE" ]]; then
    echo "Output written to $OUTPUT_FILE"
    head -n 20 "$OUTPUT_FILE"
else
    echo "Error: Output file $OUTPUT_FILE was not created"
    exit 1
fi