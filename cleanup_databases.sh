#!/bin/bash
#
# Database Cleanup Script
# Removes database files older than specified retention period
# Run weekly via cron (recommended: Sunday night)
#

SCRIPT_DIR="/root/FyersSaveData"
cd "$SCRIPT_DIR" || exit 1

echo "========================================================================"
echo "Database Cleanup Started: $(date '+%Y-%m-%d %H:%M:%S')"
echo "========================================================================"

# Activate virtual environment
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
    echo "✓ Virtual environment activated"
else
    echo "✗ Virtual environment not found!"
    exit 1
fi

# Configuration
RETENTION_DAYS=${1:-30}  # Default: keep last 30 days
DATA_DIR="data"

echo ""
echo "Configuration:"
echo "  Retention Period: $RETENTION_DAYS days"
echo "  Data Directory: $DATA_DIR"
echo ""

# Check if data directory exists
if [ ! -d "$DATA_DIR" ]; then
    echo "✗ Data directory not found: $DATA_DIR"
    exit 1
fi

# Count current database files
TOTAL_FILES=$(find "$DATA_DIR" -name "fyers_market_data_*.db" -type f | wc -l)
echo "Found $TOTAL_FILES database files"

if [ $TOTAL_FILES -eq 0 ]; then
    echo "No database files to clean up"
    exit 0
fi

# List files older than retention period
echo ""
echo "Files older than $RETENTION_DAYS days:"
OLD_FILES=$(find "$DATA_DIR" -name "fyers_market_data_*.db" -type f -mtime +$RETENTION_DAYS)

if [ -z "$OLD_FILES" ]; then
    echo "No files to remove"
    exit 0
fi

# Display files to be removed with sizes
echo ""
TOTAL_SIZE=0
COUNT=0
while IFS= read -r file; do
    if [ -f "$file" ]; then
        SIZE=$(du -h "$file" | cut -f1)
        SIZE_BYTES=$(du -b "$file" | cut -f1)
        DATE=$(basename "$file" | grep -oP '\d{8}' | sed 's/\(....\)\(..\)\(..\)/\1-\2-\3/')
        echo "  - $DATE: $file ($SIZE)"
        TOTAL_SIZE=$((TOTAL_SIZE + SIZE_BYTES))
        COUNT=$((COUNT + 1))
    fi
done <<< "$OLD_FILES"

# Convert total size to human readable
TOTAL_SIZE_MB=$((TOTAL_SIZE / 1024 / 1024))

echo ""
echo "Summary:"
echo "  Files to remove: $COUNT"
echo "  Space to free: ${TOTAL_SIZE_MB} MB"
echo ""

# Interactive mode if running manually
if [ -t 0 ]; then
    read -p "Proceed with deletion? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Cleanup cancelled"
        exit 0
    fi
fi

# Remove old files
echo "Removing old database files..."
REMOVED=0
FAILED=0

while IFS= read -r file; do
    if [ -f "$file" ]; then
        if rm "$file" 2>/dev/null; then
            echo "  ✓ Removed: $file"
            REMOVED=$((REMOVED + 1))
        else
            echo "  ✗ Failed: $file"
            FAILED=$((FAILED + 1))
        fi
    fi
done <<< "$OLD_FILES"

echo ""
echo "========================================================================"
echo "Cleanup Completed: $(date '+%Y-%m-%d %H:%M:%S')"
echo "========================================================================"
echo "Files removed: $REMOVED"
echo "Files failed: $FAILED"
echo "Space freed: ${TOTAL_SIZE_MB} MB"
echo ""

# Show remaining files
REMAINING=$(find "$DATA_DIR" -name "fyers_market_data_*.db" -type f | wc -l)
echo "Remaining database files: $REMAINING"

exit 0