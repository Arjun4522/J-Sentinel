#!/bin/bash
# update.sh - Update J-Sentinel deployment

set -e

echo "🔄 Updating J-Sentinel..."

# Pull latest changes
if [ -d ".git" ]; then
    echo "📥 Pulling latest changes..."
    git pull
fi

# Rebuild and restart
echo "🔨 Rebuilding Docker image..."
docker build -t j-sentinel:latest .

echo "🔄 Restarting services..."
if command -v docker-compose &> /dev/null; then
    docker-compose down
    docker-compose up -d
else
    docker compose down
    docker compose up -d
fi

echo "✅ J-Sentinel updated successfully!"