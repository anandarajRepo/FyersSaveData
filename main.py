"""
Enhanced main.py with automatic ATM symbol generation
Integrates symbol_generator.py for daily automated option symbol creation
"""

import sqlite3
import json
import logging
import threading
import time
import os
import sys
from datetime import datetime, timedelta
import queue
from fyers_apiv3 import fyersModel
from fyers_apiv3.FyersWebsocket import data_ws
import pandas as pd
from typing import Dict, List, Optional, Tuple
from dotenv import load_dotenv

# Import the ATM symbol generator
from symbol_generator import ATMSymbolGenerator

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('fyers_streaming.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


# Import all classes from original main.py
# (DatabaseManager, FyersAuthManager, FyersDataStreamerV3)
# [Previous classes remain the same - I'll keep them for completeness]

class SymbolManager:
    """Manages symbol generation and persistence"""

    def __init__(self, symbols_file: str = "daily_symbols.json"):
        self.symbols_file = symbols_file
        self.generator = None

    def initialize_generator(self, client_id: str, access_token: str):
        """Initialize the ATM symbol generator"""
        self.generator = ATMSymbolGenerator(client_id, access_token)
        logger.info("Symbol generator initialized")

    def generate_daily_symbols(
            self,
            indices: List[str] = None,
            num_strikes_otm: int = 1,
            include_spot: bool = False,
            save_to_file: bool = True
    ) -> List[str]:
        """
        Generate ATM symbols for the day

        Args:
            indices: List of indices (None = all)
            num_strikes_otm: Number of OTM strikes on each side
            include_spot: Include spot index symbols
            save_to_file: Save symbols to JSON file

        Returns:
            List of symbols
        """
        if not self.generator:
            logger.error("Generator not initialized")
            return []

        try:
            logger.info("Generating daily ATM symbols...")

            # Use all indices if not specified
            if indices is None:
                indices = ['NIFTY', 'BANKNIFTY', 'FINNIFTY', 'MIDCPNIFTY']

            # Generate symbols
            symbols = self.generator.get_all_atm_symbols_flat(
                indices=indices,
                num_strikes_otm=num_strikes_otm,
                include_spot=include_spot
            )

            logger.info(f"Generated {len(symbols)} symbols")

            # Save to file
            if save_to_file and symbols:
                self.save_symbols_to_file(symbols, indices, num_strikes_otm)

            return symbols

        except Exception as e:
            logger.error(f"Error generating symbols: {e}")
            return []

    def save_symbols_to_file(
            self,
            symbols: List[str],
            indices: List[str],
            num_strikes_otm: int
    ):
        """Save symbols to JSON file with metadata"""
        try:
            data = {
                'date': datetime.now().strftime('%Y-%m-%d'),
                'timestamp': datetime.now().isoformat(),
                'indices': indices,
                'num_strikes_otm': num_strikes_otm,
                'total_symbols': len(symbols),
                'symbols': symbols
            }

            with open(self.symbols_file, 'w') as f:
                json.dump(data, f, indent=2)

            logger.info(f"Symbols saved to {self.symbols_file}")

        except Exception as e:
            logger.error(f"Error saving symbols to file: {e}")

    def load_symbols_from_file(self) -> Optional[List[str]]:
        """Load symbols from file if they exist and are for today"""
        try:
            if not os.path.exists(self.symbols_file):
                logger.info("No saved symbols file found")
                return None

            with open(self.symbols_file, 'r') as f:
                data = json.load(f)

            file_date = data.get('date')
            today = datetime.now().strftime('%Y-%m-%d')

            if file_date == today:
                symbols = data.get('symbols', [])
                logger.info(f"Loaded {len(symbols)} symbols from file (today's symbols)")
                return symbols
            else:
                logger.info(f"Saved symbols are from {file_date}, not today ({today})")
                return None

        except Exception as e:
            logger.error(f"Error loading symbols from file: {e}")
            return None

    def get_or_generate_symbols(
            self,
            indices: List[str] = None,
            num_strikes_otm: int = 1,
            force_regenerate: bool = False
    ) -> List[str]:
        """
        Get symbols - load from file if available for today, otherwise generate

        Args:
            indices: List of indices
            num_strikes_otm: Number of OTM strikes
            force_regenerate: Force regeneration even if file exists

        Returns:
            List of symbols
        """
        if not force_regenerate:
            # Try to load from file first
            symbols = self.load_symbols_from_file()
            if symbols:
                return symbols

        # Generate new symbols
        logger.info("Generating new symbols...")
        return self.generate_daily_symbols(indices, num_strikes_otm)


def interactive_symbol_generator(client_id: str, access_token: str) -> List[str]:
    """Interactive symbol generation menu"""
    print("\n" + "=" * 80)
    print(" ATM OPTION SYMBOL GENERATOR")
    print("=" * 80)

    symbol_manager = SymbolManager()
    symbol_manager.initialize_generator(client_id, access_token)

    # Check for existing symbols
    existing_symbols = symbol_manager.load_symbols_from_file()
    if existing_symbols:
        print(f"\n Found {len(existing_symbols)} symbols saved for today")
        print(f" Sample symbols:")
        for sym in existing_symbols[:5]:
            print(f"   - {sym}")
        if len(existing_symbols) > 5:
            print(f"   ... and {len(existing_symbols) - 5} more")

        use_existing = input("\n Use these symbols? (y/n) [y]: ").strip().lower()
        if use_existing != 'n':
            return existing_symbols

    # Index selection
    print("\n Select indices (comma-separated numbers):")
    print("   1. NIFTY")
    print("   2. BANKNIFTY")
    print("   3. FINNIFTY")
    print("   4. MIDCPNIFTY")
    print("   5. All indices")

    choice = input("\n Enter choices (e.g., 1,2 or 5 for all) [5]: ").strip()

    if choice == '5' or not choice:
        indices = ['NIFTY', 'BANKNIFTY', 'FINNIFTY', 'MIDCPNIFTY']
    else:
        index_map = {
            '1': 'NIFTY',
            '2': 'BANKNIFTY',
            '3': 'FINNIFTY',
            '4': 'MIDCPNIFTY'
        }
        selected = choice.split(',')
        indices = [index_map.get(s.strip()) for s in selected if s.strip() in index_map]

        if not indices:
            print(" Invalid selection, using all indices")
            indices = ['NIFTY', 'BANKNIFTY', 'FINNIFTY', 'MIDCPNIFTY']

    print(f"\n Selected indices: {', '.join(indices)}")

    # OTM strikes
    print("\n Number of OTM strikes on each side:")
    print("   0 = ATM only (2 symbols per index: 1 CE + 1 PE)")
    print("   1 = ATM + 1 OTM (6 symbols per index)")
    print("   2 = ATM + 2 OTM (10 symbols per index)")

    num_otm = input("\n Enter number [1]: ").strip()
    num_strikes_otm = int(num_otm) if num_otm.isdigit() else 1

    # Include spot
    include_spot = input("\n Include spot index symbols? (y/n) [n]: ").strip().lower() == 'y'

    # Generate symbols
    print("\n Generating symbols...")
    symbols = symbol_manager.generate_daily_symbols(
        indices=indices,
        num_strikes_otm=num_strikes_otm,
        include_spot=include_spot
    )

    if symbols:
        print(f"\n Generated {len(symbols)} symbols:")
        print("\n All symbols:")
        for sym in symbols:
            print(f"   - {sym}")

        print(f"\n Symbols saved to: {symbol_manager.symbols_file}")
    else:
        print(" Failed to generate symbols")

    return symbols


def show_menu_enhanced():
    """Enhanced menu with symbol generation"""
    print("\n" + "=" * 60)
    print(" FYERS DATA STREAMING - ATM SYMBOL GENERATOR")
    print("=" * 60)
    print("1. Setup Authentication")
    print("2. Test Authentication")
    print("3. Generate ATM Symbols (Interactive)")
    print("4. Start Data Streaming (Auto-generate symbols)")
    print("5. Start Data Streaming (Use saved symbols)")
    print("6. View Streaming Stats")
    print("7. View Database Summary")
    print("8. Cleanup Old Databases")
    print("9. Update PIN")
    print("10. Exit")
    print("=" * 60)


def main_enhanced():
    """Enhanced main function with symbol generation"""

    # Handle command line arguments
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()

        if command == "auth":
            setup_authentication()
            return
        elif command == "test-auth":
            test_authentication()
            return
        elif command == "generate-symbols":
            # Direct symbol generation
            auth_manager = FyersAuthManager()
            access_token = auth_manager.get_valid_access_token()
            if access_token:
                client_id = os.environ.get('FYERS_CLIENT_ID')
                interactive_symbol_generator(client_id, access_token)
            return
        elif command == "stream":
            # Direct streaming with auto-generated symbols
            pass
        elif command == "cleanup":
            cleanup_old_databases()
            return
        else:
            print("Available commands:")
            print("  python main_enhanced.py auth              - Setup authentication")
            print("  python main_enhanced.py test-auth         - Test authentication")
            print("  python main_enhanced.py generate-symbols  - Generate ATM symbols")
            print("  python main_enhanced.py stream            - Start streaming (auto-generate)")
            print("  python main_enhanced.py cleanup           - Cleanup old databases")
            print("  python main_enhanced.py                   - Interactive menu")
            return

    # Interactive mode
    if len(sys.argv) == 1:
        use_auto_symbols = False
        use_saved_symbols = False

        while True:
            show_menu_enhanced()
            choice = input(" Select option (1-10): ").strip()

            if choice == "1":
                setup_authentication()
            elif choice == "2":
                test_authentication()
            elif choice == "3":
                # Generate symbols interactively
                auth_manager = FyersAuthManager()
                access_token = auth_manager.get_valid_access_token()
                if access_token:
                    client_id = os.environ.get('FYERS_CLIENT_ID')
                    interactive_symbol_generator(client_id, access_token)
            elif choice == "4":
                use_auto_symbols = True
                break
            elif choice == "5":
                use_saved_symbols = True
                break
            elif choice == "6":
                show_streaming_stats()
            elif choice == "7":
                show_database_summary()
            elif choice == "8":
                cleanup_old_databases()
            elif choice == "9":
                update_pin()
            elif choice == "10":
                print(" Goodbye!")
                return
            else:
                print(" Invalid choice. Please select 1-10.")
    else:
        use_auto_symbols = True  # For command line streaming

    # Main streaming logic
    try:
        print("\n" + "=" * 60)
        print(" STARTING FYERS DATA STREAMING")
        print("=" * 60)

        # Authentication
        auth_manager = FyersAuthManager()
        access_token = auth_manager.get_valid_access_token()

        if not access_token:
            print(" Authentication failed!")
            print(" Please run: python main_enhanced.py auth")
            return

        CLIENT_ID = os.environ.get('FYERS_CLIENT_ID')

        # Symbol generation
        symbol_manager = SymbolManager()
        symbol_manager.initialize_generator(CLIENT_ID, access_token)

        if use_auto_symbols:
            print("\n Generating ATM symbols automatically...")
            # Default: All indices, ATM + 1 OTM on each side
            SYMBOLS = symbol_manager.get_or_generate_symbols(
                indices=['NIFTY', 'BANKNIFTY', 'FINNIFTY', 'MIDCPNIFTY'],
                num_strikes_otm=1,
                force_regenerate=False
            )
        else:
            # Try to load saved symbols
            SYMBOLS = symbol_manager.load_symbols_from_file()
            if not SYMBOLS:
                print("\n No saved symbols found, generating new...")
                SYMBOLS = symbol_manager.generate_daily_symbols()

        if not SYMBOLS:
            print(" Failed to get symbols!")
            return

        # Initialize database manager
        db_manager = DatabaseManager()
        current_db_path = db_manager.get_current_db_path()

        print(f"\n Configuration:")
        print(f"   Client ID: {CLIENT_ID}")
        print(f"   Symbols: {len(SYMBOLS)}")
        print(f"   Database: {current_db_path}")
        print(f"   Trading Date: {datetime.now().strftime('%Y-%m-%d')}")

        print(f"\n Symbols to stream:")
        for sym in SYMBOLS:
            print(f"   - {sym}")

        # Confirm
        confirm = input("\n Start streaming? (y/n) [y]: ").strip().lower()
        if confirm == 'n':
            print(" Streaming cancelled")
            return

        # Initialize and start streamer
        streamer = FyersDataStreamerV3(CLIENT_ID, access_token, db_manager)

        print(f"\n Initializing WebSocket connection...")
        streamer.start_streaming(SYMBOLS, data_type="SymbolUpdate")

    except KeyboardInterrupt:
        print(f"\n Received interrupt signal (Ctrl+C)")
        print(f" Stopping streaming gracefully...")
        if 'streamer' in locals():
            streamer.stop_streaming()
        print(f" Streaming stopped successfully!")
        print(f" Data saved to: {streamer.current_db_path}")

    except Exception as e:
        print(f"\n Application error: {e}")
        logging.error(f"Fatal application error: {e}", exc_info=True)
        if 'streamer' in locals():
            streamer.stop_streaming()


# NOTE: Include all the original classes from main.py here
# For brevity, I'm showing just the integration points
# In the actual file, you would copy all the original classes:
# - DatabaseManager
# - FyersAuthManager
# - FyersDataStreamerV3
# - setup_authentication()
# - test_authentication()
# - show_streaming_stats()
# - show_database_summary()
# - cleanup_old_databases()
# - update_pin()


if __name__ == "__main__":
    main_enhanced()