#!/bin/bash
# monitor.sh - Monitor J-Sentinel health and performance

echo "📊 J-Sentinel Health Monitor"
echo "============================"

# Check container status
echo "🐳 Container Status:"
docker ps --filter name=j-sentinel --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo ""

# Check health
echo "❤️ Health Check:"
HEALTH=$(curl -s -u user:secret http://localhost:8080/actuator/health 2>/dev/null || echo "Failed to connect")
echo $HEALTH | jq . 2>/dev/null || echo $HEALTH

echo ""

# Check recent logs
echo "📝 Recent Logs (last 20 lines):"
docker logs --tail 20 j-sentinel

echo ""

# Check disk usage
echo "💾 Disk Usage:"
du -sh data/

echo ""

# Check active scans
echo "🔍 Recent Scans:"
curl -s -u user:secret http://localhost:8080/api/scans 2>/dev/null | jq '.[] | {id: .scanId, status: .status, created: .createdAt}' || echo "Could not fetch scan data"