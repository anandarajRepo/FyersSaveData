# Favorite Symbols Feature

This document explains how to add and manage your favorite equity stocks for tick data collection.

## Overview

The FyersSaveData project now supports collecting tick data for your favorite equity stocks alongside the auto-generated ATM option symbols.

## Configuration File

The favorite symbols are stored in `favorite_symbols.json` at the project root.

### File Structure

```json
{
  "description": "User's favorite stocks for tick data collection",
  "symbols": {
    "STLNETWORK": "NSE:STLNETWORK-EQ",
    "STLTECH": "NSE:STLTECH-EQ",
    "SKYGOLD": "NSE:SKYGOLD-EQ"
  },
  "enabled": true
}
```

### Fields

- `description`: A description of the favorite symbols list
- `symbols`: A dictionary mapping symbol names to their Fyers format symbols
  - Key: A friendly name for the symbol (used for reference)
  - Value: The Fyers symbol format (e.g., `NSE:SYMBOL-EQ` for equity)
- `enabled`: Boolean flag to enable/disable favorite symbols (set to `false` to temporarily disable)

## Adding New Symbols

To add new favorite symbols:

1. Open `favorite_symbols.json` in a text editor
2. Add a new entry to the `symbols` object:
   ```json
   "NEWSYMBOL": "NSE:NEWSYMBOL-EQ"
   ```
3. Save the file
4. The next streaming session will automatically include these symbols

## Fyers Symbol Format

For equity stocks, use the format: `NSE:SYMBOL-EQ`

Examples:
- `NSE:RELIANCE-EQ`
- `NSE:TCS-EQ`
- `NSE:INFY-EQ`

For other instrument types, refer to the [Fyers Symbology Documentation](https://myapi.fyers.in/docsv3#tag/Appendix/Symbology-Format).

## Disabling Favorite Symbols

To temporarily stop collecting data for favorite symbols without deleting them:

1. Open `favorite_symbols.json`
2. Change `"enabled": true` to `"enabled": false`
3. Save the file

## How It Works

When you start streaming:

1. The system generates ATM option symbols for selected indices (NIFTY, BANKNIFTY, etc.)
2. It then loads favorite symbols from `favorite_symbols.json`
3. Both sets of symbols are combined and streamed together
4. All tick data is saved to the same database

## Database Storage

Favorite symbols are stored in the same database tables as option symbols:

- Tick data: `market_data` table
- Market depth: `market_depth` table
- Database location: `data/fyers_market_data_YYYYMMDD.db`

You can query specific symbols using SQL:

```sql
SELECT * FROM market_data WHERE symbol = 'NSE:STLNETWORK-EQ';
```

## Notes

- Favorite symbols are loaded on every streaming session
- Changes to `favorite_symbols.json` take effect immediately on the next run
- There's no limit to the number of favorite symbols, but consider API rate limits
- Favorite symbols work alongside auto-generated symbols, not as a replacement
