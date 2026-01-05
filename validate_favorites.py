#!/usr/bin/env python3
"""
Simple validation script for favorite_symbols.json
"""

import json

def validate_favorite_symbols():
    """Validate favorite_symbols.json format"""
    print("Validating favorite_symbols.json...")
    print()

    with open('favorite_symbols.json', 'r') as f:
        data = json.load(f)

    # Validate structure
    assert 'symbols' in data, "Missing 'symbols' key"
    assert 'enabled' in data, "Missing 'enabled' key"
    assert isinstance(data['symbols'], dict), "'symbols' should be a dictionary"
    assert isinstance(data['enabled'], bool), "'enabled' should be a boolean"

    symbols = list(data['symbols'].values())
    print(f"Status: {'Enabled ✓' if data['enabled'] else 'Disabled ✗'}")
    print(f"Total symbols: {len(symbols)}")
    print()
    print("Favorite symbols:")
    print("-" * 40)

    for name, symbol in data['symbols'].items():
        # Validate Fyers format
        assert symbol.startswith('NSE:'), f"Symbol {symbol} should start with 'NSE:'"
        assert symbol.endswith('-EQ'), f"Symbol {symbol} should end with '-EQ' for equity"
        print(f"  ✓ {name:15s} → {symbol}")

    print("-" * 40)
    print()
    print("✓ All symbols are valid Fyers equity format")
    print("✓ Configuration file is valid")
    print()
    print("These symbols will be automatically included in your")
    print("next streaming session alongside generated ATM options.")

if __name__ == '__main__':
    try:
        validate_favorite_symbols()
    except FileNotFoundError:
        print("✗ Error: favorite_symbols.json not found")
        print("  Please create the file using the template in FAVORITE_SYMBOLS.md")
    except json.JSONDecodeError as e:
        print(f"✗ Error: Invalid JSON format: {e}")
    except AssertionError as e:
        print(f"✗ Validation error: {e}")
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
