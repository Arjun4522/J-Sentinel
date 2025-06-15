#!/bin/bash
# deploy.sh - Automated deployment script for J-Sentinel

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🛡️ J-Sentinel Deployment Script${NC}"
echo "=================================="

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    print_error "Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Set deployment mode
DEPLOYMENT_MODE=${1:-development}

print_status "Deployment mode: $DEPLOYMENT_MODE"

# Create necessary directories
print_status "Creating required directories..."
mkdir -p data/{db,uploads,outputs,logs}
mkdir -p monitoring

# Set environment variables
if [ "$DEPLOYMENT_MODE" = "production" ]; then
    print_status "Setting up production environment..."
    
    # Check if required environment variables are set
    if [ -z "$J_SENTINEL_PASSWORD" ]; then
        print_error "J_SENTINEL_PASSWORD environment variable is required for production deployment"
        exit 1
    fi
    
    # Create production directories
    sudo mkdir -p /opt/j-sentinel/{db,uploads,outputs,logs}
    sudo chown -R $USER:$USER /opt/j-sentinel/
    
    # Use production compose file
    COMPOSE_FILE="docker-compose.yml"
    export J_SENTINEL_USER=${J_SENTINEL_USER:-admin}
    export SCAN_SOURCE_DIR=${SCAN_SOURCE_DIR:-/projects}
else
    print_status "Setting up development environment..."
    COMPOSE_FILE="docker-compose.yml"
fi

# Build and start services
print_status "Building J-Sentinel Docker image..."
docker build -t j-sentinel:latest .

if [ $? -eq 0 ]; then
    print_status "✅ Docker image built successfully"
else
    print_error "❌ Failed to build Docker image"
    exit 1
fi

print_status "Starting J-Sentinel services..."
if command -v docker-compose &> /dev/null; then
    docker-compose -f $COMPOSE_FILE up -d
else
    docker compose -f $COMPOSE_FILE up -d
fi

# Wait for service to be ready
print_status "Waiting for J-Sentinel to be ready..."
timeout=60
counter=0

while [ $counter -lt $timeout ]; do
    if curl -f -u user:secret http://localhost:8080/actuator/health &> /dev/null; then
        print_status "✅ J-Sentinel is ready!"
        break
    fi
    
    if [ $counter -eq 30 ]; then
        print_warning "Still waiting for J-Sentinel to start..."
    fi
    
    sleep 2
    counter=$((counter + 2))
done

if [ $counter -ge $timeout ]; then
    print_error "❌ J-Sentinel failed to start within $timeout seconds"
    print_status "Checking logs..."
    docker logs j-sentinel
    exit 1
fi

# Run health check
print_status "Running health check..."
HEALTH_STATUS=$(curl -s -u user:secret http://localhost:8080/actuator/health | grep -o '"status":"[^"]*' | cut -d'"' -f4)

if [ "$HEALTH_STATUS" = "UP" ]; then
    print_status "✅ Health check passed"
else
    print_error "❌ Health check failed: $HEALTH_STATUS"
    exit 1
fi

# Test API endpoints
print_status "Testing API endpoints..."

# Test scans endpoint
if curl -s -u user:secret http://localhost:8080/api/scans &> /dev/null; then
    print_status "✅ Scans API endpoint is working"
else
    print_warning "⚠️ Scans API endpoint test failed"
fi

# Test history endpoint
if curl -s -u user:secret http://localhost:8080/api/history/scans &> /dev/null; then
    print_status "✅ History API endpoint is working"
else
    print_warning "⚠️ History API endpoint test failed"
fi

print_status "🎉 J-Sentinel deployment completed successfully!"
echo ""
echo "=================================="
echo -e "${GREEN}🛡️ J-Sentinel is now running!${NC}"
echo ""
echo "📊 Dashboard: http://localhost:8080"
echo "🔍 API Documentation: http://localhost:8080/swagger-ui.html"
echo "❤️ Health Check: http://localhost:8080/actuator/health"
echo ""
echo "📝 API Usage Examples:"
echo "  curl -u user:secret http://localhost:8080/api/scans"
echo "  curl -u user:secret http://localhost:8080/api/history/scans"
echo ""
echo "🔧 Useful Commands:"
echo "  docker logs j-sentinel              # View logs"
echo "  docker exec -it j-sentinel bash    # Access container"
echo "  docker-compose down                 # Stop services"
echo "  docker-compose logs -f              # Follow logs"
echo "=================================="