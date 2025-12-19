#!/bin/bash
#
# Refresh ATM Option Symbols Script
# Automatically generates fresh option symbols based on current spot prices
# Run this before market hours (recommended: 8:00 AM IST)
#

# Clear previous log
truncate -s 0 /var/log/savedata.log

# Script directory
SCRIPT_DIR="/root/FyersSaveData"
cd "$SCRIPT_DIR" || exit 1

# Log header
echo "========================================================================"
echo "Symbol Refresh Started: $(date '+%Y-%m-%d %H:%M:%S %A')"
echo "========================================================================"

# Activate virtual environment
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
    echo "✓ Virtual environment activated"
else
    echo "✗ Virtual environment not found!"
    exit 1
fi

# Check if it's a trading day (Monday-Friday)
DAY_OF_WEEK=$(date +%u)  # 1-7 (Monday-Sunday)
if [ "$DAY_OF_WEEK" -gt 5 ]; then
    echo "⚠ Today is $(date +%A) - not a trading day"
    echo "Skipping symbol refresh"
    exit 0
fi

echo "✓ Trading day confirmed: $(date +%A)"

# Configuration
INDICES="NIFTY BANKNIFTY FINNIFTY MIDCPNIFTY"
OTM_STRIKES=1
OUTPUT_FILE="daily_symbols.json"

echo ""
echo "Configuration:"
echo "  Indices: $INDICES"
echo "  OTM Strikes: $OTM_STRIKES on each side"
echo "  Output: $OUTPUT_FILE"
echo ""

# Run symbol refresh
echo "Generating ATM symbols..."
python3.11 refresh_symbols.py \
    --indices $INDICES \
    --otm-strikes $OTM_STRIKES \
    --output "$OUTPUT_FILE"

# Check if successful
if [ $? -eq 0 ]; then
    echo ""
    echo "========================================================================"
    echo "✓ Symbol refresh completed successfully: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "========================================================================"

    # Display symbol count
    if [ -f "$OUTPUT_FILE" ]; then
        SYMBOL_COUNT=$(python3.11 -c "import json; print(json.load(open('$OUTPUT_FILE'))['total_symbols'])" 2>/dev/null)
        if [ -n "$SYMBOL_COUNT" ]; then
            echo "Generated $SYMBOL_COUNT symbols for today"
        fi

        # Display first few symbols as verification
        echo ""
        echo "Sample symbols:"
        python3.11 -c "import json; data = json.load(open('$OUTPUT_FILE')); [print('  -', s) for s in data['symbols'][:8]]" 2>/dev/null
    fi

    echo ""
    echo "Symbols saved to: $SCRIPT_DIR/$OUTPUT_FILE"
    echo "Ready for data streaming!"

    exit 0
else
    echo ""
    echo "========================================================================"
    echo "✗ Symbol refresh failed: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "========================================================================"
    echo "Please check the logs above for errors"
    echo "Common issues:"
    echo "  - Invalid or expired access token"
    echo "  - Network connectivity problems"
    echo "  - API rate limits exceeded"
    echo ""
    echo "To fix authentication:"
    echo "  cd $SCRIPT_DIR"
    echo "  source venv/bin/activate"
    echo "  python3.11 main.py auth"

    exit 1
fi