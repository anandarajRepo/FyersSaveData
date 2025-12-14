#!/bin/bash
#
# Status Check Script
# Monitors data streaming processes and symbol status
# Can be run manually or via cron for automated monitoring
#

SCRIPT_DIR="/root/FyersSaveData"
cd "$SCRIPT_DIR" || exit 1

# Colors for terminal output (if running interactively)
if [ -t 1 ]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[1;33m'
    NC='\033[0m' # No Color
else
    GREEN=''
    RED=''
    YELLOW=''
    NC=''
fi

echo "========================================================================"
echo "System Status Check: $(date '+%Y-%m-%d %H:%M:%S %A')"
echo "========================================================================"

# Check if today is a trading day
DAY_OF_WEEK=$(date +%u)
if [ "$DAY_OF_WEEK" -gt 5 ]; then
    echo -e "${YELLOW}⚠ Today is $(date +%A) - not a trading day${NC}"
    TRADING_DAY=false
else
    echo -e "${GREEN}✓ Trading day: $(date +%A)${NC}"
    TRADING_DAY=true
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SYMBOL STATUS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check symbol file
SYMBOLS_FILE="daily_symbols.json"
if [ -f "$SYMBOLS_FILE" ]; then
    # Extract symbol information
    SYMBOL_DATE=$(python3 -c "import json; print(json.load(open('$SYMBOLS_FILE'))['date'])" 2>/dev/null)
    SYMBOL_COUNT=$(python3 -c "import json; print(json.load(open('$SYMBOLS_FILE'))['total_symbols'])" 2>/dev/null)
    SYMBOL_TIME=$(python3 -c "import json; from datetime import datetime; ts = json.load(open('$SYMBOLS_FILE'))['timestamp']; dt = datetime.fromisoformat(ts); print(dt.strftime('%H:%M:%S'))" 2>/dev/null)

    TODAY=$(date '+%Y-%m-%d')

    if [ "$SYMBOL_DATE" = "$TODAY" ]; then
        echo -e "${GREEN}✓ Symbol file: Up to date (today)${NC}"
        echo "  Date: $SYMBOL_DATE"
        echo "  Generated: $SYMBOL_TIME"
        echo "  Count: $SYMBOL_COUNT symbols"

        # Show sample symbols
        echo "  Sample:"
        python3 -c "import json; data = json.load(open('$SYMBOLS_FILE')); [print('    -', s) for s in data['symbols'][:4]]" 2>/dev/null
    else
        echo -e "${YELLOW}⚠ Symbol file: OUTDATED${NC}"
        echo "  File date: $SYMBOL_DATE"
        echo "  Today: $TODAY"
        echo "  Status: Symbols need refresh!"

        if [ "$TRADING_DAY" = true ]; then
            echo -e "  ${YELLOW}Action: Run refresh_symbols.sh${NC}"
        fi
    fi
else
    echo -e "${RED}✗ Symbol file: NOT FOUND${NC}"
    echo "  Expected: $SYMBOLS_FILE"

    if [ "$TRADING_DAY" = true ]; then
        echo -e "  ${RED}Action: Run refresh_symbols.sh immediately${NC}"
    fi
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "PROCESS STATUS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check if streaming process is running
STREAMING_PROCESS=$(pgrep -f "main.py stream")

if [ -n "$STREAMING_PROCESS" ]; then
    echo -e "${GREEN}✓ Data streaming: RUNNING${NC}"
    echo "  PID: $STREAMING_PROCESS"

    # Check how long it's been running
    UPTIME=$(ps -p $STREAMING_PROCESS -o etime= | tr -d ' ')
    echo "  Uptime: $UPTIME"

    # Check memory usage
    MEM=$(ps -p $STREAMING_PROCESS -o %mem= | tr -d ' ')
    echo "  Memory: ${MEM}%"
else
    if [ "$TRADING_DAY" = true ]; then
        CURRENT_HOUR=$(date +%H)
        if [ $CURRENT_HOUR -ge 9 ] && [ $CURRENT_HOUR -lt 16 ]; then
            echo -e "${RED}✗ Data streaming: NOT RUNNING (should be running!)${NC}"
            echo -e "  ${RED}Action: Run run_savedata.sh${NC}"
        else
            echo -e "${YELLOW}⚠ Data streaming: NOT RUNNING (outside market hours)${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ Data streaming: NOT RUNNING (weekend)${NC}"
    fi
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "DATABASE STATUS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check today's database
DATA_DIR="data"
TODAY_DB="fyers_market_data_$(date +%Y%m%d).db"
TODAY_DB_PATH="$DATA_DIR/$TODAY_DB"

if [ -f "$TODAY_DB_PATH" ]; then
    echo -e "${GREEN}✓ Today's database: EXISTS${NC}"

    # Get database stats
    DB_SIZE=$(du -h "$TODAY_DB_PATH" | cut -f1)
    echo "  File: $TODAY_DB"
    echo "  Size: $DB_SIZE"

    # Get record count using Python
    source venv/bin/activate 2>/dev/null
    RECORD_COUNT=$(python3 -c "
import sqlite3
try:
    conn = sqlite3.connect('$TODAY_DB_PATH')
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM market_data')
    print(cursor.fetchone()[0])
    conn.close()
except: pass
" 2>/dev/null)

    if [ -n "$RECORD_COUNT" ]; then
        echo "  Records: ${RECORD_COUNT}"

        # Get latest record time
        LATEST_TIME=$(python3 -c "
import sqlite3
try:
    conn = sqlite3.connect('$TODAY_DB_PATH')
    cursor = conn.cursor()
    cursor.execute('SELECT MAX(timestamp) FROM market_data')
    ts = cursor.fetchone()[0]
    if ts:
        from datetime import datetime
        dt = datetime.fromisoformat(ts)
        print(dt.strftime('%H:%M:%S'))
    conn.close()
except: pass
" 2>/dev/null)

        if [ -n "$LATEST_TIME" ]; then
            echo "  Latest: $LATEST_TIME"
        fi
    fi
else
    if [ "$TRADING_DAY" = true ]; then
        CURRENT_HOUR=$(date +%H)
        if [ $CURRENT_HOUR -ge 9 ]; then
            echo -e "${RED}✗ Today's database: NOT FOUND (streaming not started!)${NC}"
            echo "  Expected: $TODAY_DB_PATH"
        else
            echo -e "${YELLOW}⚠ Today's database: NOT FOUND (before market hours)${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ Today's database: NOT FOUND (weekend)${NC}"
    fi
fi

# Count total databases
if [ -d "$DATA_DIR" ]; then
    TOTAL_DBS=$(find "$DATA_DIR" -name "fyers_market_data_*.db" -type f | wc -l)
    echo ""
    echo "Total databases: $TOTAL_DBS"

    # Calculate total size
    TOTAL_SIZE=$(du -sh "$DATA_DIR" 2>/dev/null | cut -f1)
    echo "Total size: $TOTAL_SIZE"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "LOG STATUS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check log files
LOGS=("/var/log/savedata.log" "/var/log/symbol_refresh.log" "fyers_streaming.log")

for LOG in "${LOGS[@]}"; do
    if [ -f "$LOG" ]; then
        LOG_SIZE=$(du -h "$LOG" | cut -f1)
        LOG_LINES=$(wc -l < "$LOG")
        BASENAME=$(basename "$LOG")

        echo "✓ $BASENAME:"
        echo "  Size: $LOG_SIZE"
        echo "  Lines: $LOG_LINES"

        # Show last error if any
        LAST_ERROR=$(grep -i "error" "$LOG" | tail -1 2>/dev/null)
        if [ -n "$LAST_ERROR" ]; then
            echo -e "  ${YELLOW}Last error:${NC} $(echo $LAST_ERROR | cut -c1-60)..."
        fi
    else
        echo "⚠ $(basename $LOG): Not found"
    fi
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SYSTEM RESOURCES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Disk usage
DISK_USAGE=$(df -h "$SCRIPT_DIR" | awk 'NR==2 {print $5}')
echo "Disk usage: $DISK_USAGE"

# Memory usage
MEM_USAGE=$(free | awk 'NR==2 {printf "%.1f%%", $3/$2 * 100.0}')
echo "Memory usage: $MEM_USAGE"

# Load average
LOAD=$(uptime | awk -F'load average:' '{print $2}')
echo "Load average:$LOAD"

echo ""
echo "========================================================================"
echo "Status check completed: $(date '+%Y-%m-%d %H:%M:%S')"
echo "========================================================================"

# Return status code based on critical issues
if [ "$TRADING_DAY" = true ]; then
    CURRENT_HOUR=$(date +%H)
    if [ $CURRENT_HOUR -ge 9 ] && [ $CURRENT_HOUR -lt 16 ]; then
        # Market hours - check if streaming should be running
        if [ -z "$STREAMING_PROCESS" ]; then
            echo -e "${RED}⚠ WARNING: Streaming should be running during market hours!${NC}"
            exit 1
        fi
    fi
fi

exit 0