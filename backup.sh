#!/bin/bash
# backup.sh - Backup J-Sentinel data

set -e

BACKUP_DIR="backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p $BACKUP_DIR

echo "💾 Creating backup in $BACKUP_DIR..."

# Backup database
if [ -f "data/db/data.db" ]; then
    cp data/db/data.db $BACKUP_DIR/
    echo "✅ Database backed up"
fi

# Backup outputs
if [ -d "data/outputs" ]; then
    tar -czf $BACKUP_DIR/outputs.tar.gz -C data outputs/
    echo "✅ Outputs backed up"
fi

# Backup configuration
cp docker-compose.yml $BACKUP_DIR/
cp Dockerfile $BACKUP_DIR/
echo "✅ Configuration backed up"

echo "💾 Backup completed: $BACKUP_DIR"