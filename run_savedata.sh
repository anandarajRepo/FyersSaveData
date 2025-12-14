#!/bin/bash
#
# Enhanced Run Save Data Script
# Starts data streaming with auto-generated ATM option symbols
#

# Clear previous log
truncate -s 0 /var/log/savedata.log

# Script directory
SCRIPT_DIR="/root/FyersSaveData"
cd "$SCRIPT_DIR" || exit 1

# Log header
echo "========================================================================"
echo "Data Streaming Started: $(date '+%Y-%m-%d %H:%M:%S %A')"
echo "========================================================================"

# Activate virtual environment
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
    echo "✓ Virtual environment activated"
else
    echo "✗ Virtual environment not found!"
    exit 1
fi

# Check for today's symbols
SYMBOLS_FILE="daily_symbols.json"
if [ -f "$SYMBOLS_FILE" ]; then
    # Verify symbols are for today
    SYMBOL_DATE=$(python3 -c "import json; print(json.load(open('$SYMBOLS_FILE'))['date'])" 2>/dev/null)
    TODAY=$(date '+%Y-%m-%d')

    if [ "$SYMBOL_DATE" = "$TODAY" ]; then
        SYMBOL_COUNT=$(python3 -c "import json; print(json.load(open('$SYMBOLS_FILE'))['total_symbols'])" 2>/dev/null)
        echo "✓ Using today's symbols: $SYMBOL_COUNT symbols found"
        echo "  Symbol file: $SYMBOLS_FILE"
        echo "  Generated: $SYMBOL_DATE"
    else
        echo "⚠ Warning: Symbol file is from $SYMBOL_DATE, not today ($TODAY)"
        echo "Attempting to generate fresh symbols..."

        # Try to generate fresh symbols
        python3 refresh_symbols.py

        if [ $? -ne 0 ]; then
            echo "✗ Failed to generate fresh symbols"
            echo "Proceeding with old symbols as fallback..."
        fi
    fi
else
    echo "⚠ Warning: No symbol file found ($SYMBOLS_FILE)"
    echo "Attempting to generate symbols now..."

    # Try to generate symbols
    python3 refresh_symbols.py

    if [ $? -ne 0 ]; then
        echo "✗ Failed to generate symbols"
        echo "Cannot start streaming without symbols!"
        exit 1
    fi
fi

echo ""
echo "Starting data streaming with main.py..."
echo "Press Ctrl+C to stop"
echo "========================================================================"
echo ""

# Run the streaming application
# Using 'stream' argument to skip interactive menu
python3 main.py stream >> /var/log/savedata.log 2>&1 &

# Get PID
STREAMING_PID=$!
echo "Streaming process started with PID: $STREAMING_PID"

# Save PID for monitoring
echo $STREAMING_PID > /tmp/savedata.pid

echo ""
echo "Data streaming is now running in background"
echo "Monitor logs: tail -f /var/log/savedata.log"
echo "Stop streaming: /root/FyersSaveData/stop_savedata.sh"
echo ""
echo "========================================================================"

exit 0