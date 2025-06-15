#!/bin/bash
set -e

echo "🛡️ Starting J-Sentinel..."

# Ensure required directories exist
mkdir -p /tmp/j-sentinel/uploads /tmp/j-sentinel/outputs
chmod -R 777 /tmp/j-sentinel

# Initialize database if it doesn't exist
if [ ! -f "/app/reports/data.db" ]; then
    echo "📊 Initializing SQLite database..."
    cd /app
    if [ -f "initdb.go" ] && [ -f "db_setup.go" ]; then
        go run initdb.go db_setup.go
    else
        echo "⚠️ Database initialization files not found, creating empty database..."
        sqlite3 /app/reports/data.db "CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, created_at DATETIME, status TEXT, source_dir TEXT);"
    fi
fi

# Test rule engine binary
echo "🔍 Testing rule engine..."
if [ -f "/app/rule-engine/detect" ]; then
    echo "✅ Rule engine binary found"
else
    echo "❌ Rule engine binary not found!"
    exit 1
fi

# Test Python rule engine
echo "🐍 Testing Python rule engine..."
cd /app/rule-engine
if python3 -c "import yaml, requests; print('Python dependencies OK')"; then
    echo "✅ Python dependencies verified"
else
    echo "❌ Python dependencies missing!"
    exit 1
fi

# Test Semgrep installation
echo "🔧 Testing Semgrep..."
if command -v semgrep &> /dev/null; then
    echo "✅ Semgrep is available"
    semgrep --version
else
    echo "⚠️ Semgrep not found, installing..."
    pip3 install semgrep
fi

# Set default environment variables if not provided
export API_USER=${API_USER:-user}
export API_PASSWORD=${API_PASSWORD:-secret}
export SPRING_PROFILES_ACTIVE=${SPRING_PROFILES_ACTIVE:-docker}

echo "🚀 Starting J-Sentinel API Gateway..."
echo "   API User: $API_USER"
echo "   Profile: $SPRING_PROFILES_ACTIVE"
echo "   Database: /app/reports/data.db"
echo "   Rules Directory: /app/rule-engine/rules"

# Start the Spring Boot application
cd /app
exec java -jar \
    -Dspring.profiles.active=$SPRING_PROFILES_ACTIVE \
    -Dapp.upload.dir=/tmp/j-sentinel/uploads \
    -Dapp.output.dir=/tmp/j-sentinel/outputs \
    -Dapp.rules.dir=/app/rule-engine/rules \
    -Dapp.database.path=/app/reports/data.db \
    -Djava.security.egd=file:/dev/./urandom \
    -Xmx1g \
    api-gateway/app.jar