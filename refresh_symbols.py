#!/usr/bin/env python3
"""
Daily Symbol Refresh Script
Run this via cron before market hours to generate fresh ATM symbols
Recommended: Run at 8:00 AM IST on trading days
"""

import os
import sys
import logging
from datetime import datetime
from dotenv import load_dotenv

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from symbol_generator import ATMSymbolGenerator

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('symbol_refresh.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


def is_trading_day() -> bool:
    """Check if today is a trading day (Monday-Friday)"""
    weekday = datetime.now().weekday()
    return weekday < 5  # Monday=0, Friday=4


def refresh_daily_symbols(
    indices: list = None,
    num_strikes_otm: int = 1,
    include_spot: bool = False,
    output_file: str = "daily_symbols.json"
):
    """
    Refresh daily ATM symbols

    Args:
        indices: List of indices (None = all)
        num_strikes_otm: Number of OTM strikes on each side
        include_spot: Include spot symbols
        output_file: Output JSON file
    """
    logger.info("=" * 80)
    logger.info("DAILY SYMBOL REFRESH - %s", datetime.now().strftime('%Y-%m-%d %A'))
    logger.info("=" * 80)

    # Check if trading day
    if not is_trading_day():
        logger.info("Today is not a trading day (weekend) - skipping")
        return False

    # Get credentials
    client_id = os.environ.get('FYERS_CLIENT_ID')
    access_token = os.environ.get('FYERS_ACCESS_TOKEN')

    if not client_id or not access_token:
        logger.error("Missing credentials - FYERS_CLIENT_ID or FYERS_ACCESS_TOKEN not found")
        logger.error("Please run authentication: python main.py auth")
        return False

    try:
        # Initialize generator
        logger.info("Initializing symbol generator...")
        generator = ATMSymbolGenerator(client_id, access_token)

        # Set default indices if not provided
        if indices is None:
            indices = ['NIFTY', 'BANKNIFTY', 'FINNIFTY', 'MIDCPNIFTY']

        logger.info("Configuration:")
        logger.info("  Indices: %s", ', '.join(indices))
        logger.info("  OTM Strikes: %d on each side", num_strikes_otm)
        logger.info("  Include Spot: %s", include_spot)

        # Generate symbols
        logger.info("\nGenerating ATM symbols...")
        symbols_dict = generator.generate_atm_symbols(
            indices=indices,
            num_strikes_otm=num_strikes_otm,
            include_spot=include_spot
        )

        if not symbols_dict:
            logger.error("Failed to generate symbols")
            return False

        # Flatten symbols
        all_symbols = []
        for index_name, symbols in symbols_dict.items():
            all_symbols.extend(symbols)

        logger.info("\nGenerated %d total symbols:", len(all_symbols))

        # Display symbols by index
        for index_name, symbols in symbols_dict.items():
            logger.info("\n%s (%d symbols):", index_name, len(symbols))
            for sym in symbols:
                logger.info("  - %s", sym)

        # Save to JSON file
        import json
        data = {
            'date': datetime.now().strftime('%Y-%m-%d'),
            'timestamp': datetime.now().isoformat(),
            'day_of_week': datetime.now().strftime('%A'),
            'indices': indices,
            'num_strikes_otm': num_strikes_otm,
            'include_spot': include_spot,
            'total_symbols': len(all_symbols),
            'symbols_by_index': symbols_dict,
            'symbols': all_symbols
        }

        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)

        logger.info("\nSymbols saved to: %s", output_file)
        logger.info("Symbol refresh completed successfully!")
        logger.info("=" * 80)

        return True

    except Exception as e:
        logger.error("Error during symbol refresh: %s", str(e), exc_info=True)
        return False


def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(description='Daily ATM Symbol Refresh')
    parser.add_argument(
        '--indices',
        nargs='+',
        choices=['NIFTY', 'BANKNIFTY', 'FINNIFTY', 'MIDCPNIFTY'],
        help='Indices to generate symbols for (default: all)'
    )
    parser.add_argument(
        '--otm-strikes',
        type=int,
        default=1,
        help='Number of OTM strikes on each side (default: 1)'
    )
    parser.add_argument(
        '--include-spot',
        action='store_true',
        help='Include spot index symbols'
    )
    parser.add_argument(
        '--output',
        default='daily_symbols.json',
        help='Output file path (default: daily_symbols.json)'
    )
    parser.add_argument(
        '--force',
        action='store_true',
        help='Force refresh even on weekends'
    )

    args = parser.parse_args()

    # Override trading day check if forced
    if args.force:
        logger.info("Force mode enabled - running regardless of day")
        # Temporarily override the check
        global is_trading_day
        original_check = is_trading_day
        is_trading_day = lambda: True

    # Run refresh
    success = refresh_daily_symbols(
        indices=args.indices,
        num_strikes_otm=args.otm_strikes,
        include_spot=args.include_spot,
        output_file=args.output
    )

    # Restore original check
    if args.force:
        is_trading_day = original_check

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()