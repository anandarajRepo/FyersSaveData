# Favorite Symbols Feature

This document explains how to add and manage your favorite equity stocks for tick data collection.

## Overview

The FyersSaveData project supports collecting tick data for your favorite equity stocks alongside the auto-generated ATM option symbols. Favorite symbols are defined directly in the `main.py` file.

## Configuration

Favorite symbols are defined as a constant in `main.py` (around line 49):

```python
# Favorite stocks for tick data collection
FAVORITE_SYMBOLS = [
    "NSE:STLNETWORK-EQ",
    "NSE:STLTECH-EQ",
    "NSE:SKYGOLD-EQ",
]
```

## Adding New Symbols

To add new favorite symbols:

1. Open `main.py` in a text editor
2. Locate the `FAVORITE_SYMBOLS` list (near the top of the file, after imports)
3. Add your symbols to the list:
   ```python
   FAVORITE_SYMBOLS = [
       "NSE:STLNETWORK-EQ",
       "NSE:STLTECH-EQ",
       "NSE:SKYGOLD-EQ",
       "NSE:RELIANCE-EQ",      # New symbol
       "NSE:TCS-EQ",           # New symbol
   ]
   ```
4. Save the file
5. The next streaming session will automatically include these symbols

## Fyers Symbol Format

For equity stocks, use the format: `NSE:SYMBOL-EQ`

Examples:
- `NSE:RELIANCE-EQ`
- `NSE:TCS-EQ`
- `NSE:INFY-EQ`
- `NSE:HDFCBANK-EQ`

For other instrument types, refer to the [Fyers Symbology Documentation](https://myapi.fyers.in/docsv3#tag/Appendix/Symbology-Format).

## Disabling Favorite Symbols

To temporarily stop collecting data for favorite symbols:

1. Open `main.py`
2. Comment out the symbols or set the list to empty:
   ```python
   # Temporary disable - empty list
   FAVORITE_SYMBOLS = []

   # Or comment out specific symbols:
   FAVORITE_SYMBOLS = [
       "NSE:STLNETWORK-EQ",
       # "NSE:STLTECH-EQ",      # Temporarily disabled
       "NSE:SKYGOLD-EQ",
   ]
   ```
3. Save the file

## How It Works

When you start streaming:

1. The system generates ATM option symbols for selected indices (NIFTY, BANKNIFTY, etc.)
2. It loads favorite symbols from the `FAVORITE_SYMBOLS` constant in `main.py`
3. Both sets of symbols are combined and streamed together
4. All tick data is saved to the same database

The integration happens automatically in the `SymbolManager` class:
- Auto-generate mode: Favorites added via `get_or_generate_symbols()`
- Saved symbols mode: Favorites merged with loaded symbols
- Fallback mode: Favorites loaded even when generator unavailable

## Database Storage

Favorite symbols are stored in the same database tables as option symbols:

- Tick data: `market_data` table
- Market depth: `market_depth` table
- Database location: `data/fyers_market_data_YYYYMMDD.db`

You can query specific symbols using SQL:

```sql
SELECT * FROM market_data WHERE symbol = 'NSE:STLNETWORK-EQ';
```

## Code Reference

The favorite symbols feature is implemented in:

- **Constant Definition**: `main.py:49-54` - `FAVORITE_SYMBOLS` list
- **Loading Logic**: `main.py:1143-1148` - `SymbolManager.load_favorite_symbols()`
- **Integration**: `main.py:1190-1194` - Merging favorites with generated symbols

## Notes

- Favorite symbols are loaded on every streaming session
- Changes to `FAVORITE_SYMBOLS` take effect immediately on the next run
- There's no limit to the number of favorite symbols, but consider API rate limits
- Favorite symbols work alongside auto-generated symbols, not as a replacement
- The list is defined in Python code for simplicity and version control
