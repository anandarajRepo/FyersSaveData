"""
ATM Option Symbol Generator for Fyers API
Automatically generates At-The-Money option symbols for NIFTY, BANKNIFTY, FINNIFTY, and MIDCPNIFTY
Based on Fyers Symbology Format: https://myapi.fyers.in/docsv3#tag/Appendix/Symbology-Format
"""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
import calendar
from fyers_apiv3 import fyersModel

logger = logging.getLogger(__name__)


class ATMSymbolGenerator:
    """
    Generates ATM (At-The-Money) option symbols for Indian indices

    Symbology Format: NSE:UNDERLYING[YY][MMM/D][DD]STRIKEPRICE[CE/PE]
    Examples:
        - NSE:NIFTY25DEC26000CE (Monthly expiry)
        - NSE:NIFTY25D1226000CE (Weekly expiry)
        - NSE:BANKNIFTY25JAN58000PE
    """

    # Index configurations
    INDEX_CONFIG = {
        'NIFTY': {
            'spot_symbol': 'NSE:NIFTY50-INDEX',
            'option_prefix': 'NIFTY',
            'strike_interval': 50,
            'lot_size': 50,
            'expiry_day': 1,  # Tuesday (0=Monday, 6=Sunday)
            'expiry_type': 'weekly'  # weekly or monthly
        },
        'BANKNIFTY': {
            'spot_symbol': 'NSE:NIFTYBANK-INDEX',
            'option_prefix': 'BANKNIFTY',
            'strike_interval': 100,
            'lot_size': 30,
            'expiry_day': 1,  # Tuesday
            'expiry_type': 'monthly'
        },
        'FINNIFTY': {
            'spot_symbol': 'NSE:FINNIFTY-INDEX',
            'option_prefix': 'FINNIFTY',
            'strike_interval': 50,
            'lot_size': 60,
            'expiry_day': 1,  # Tuesday
            'expiry_type': 'monthly'
        },
        'MIDCPNIFTY': {
            'spot_symbol': 'NSE:NIFTYMIDCAP50-INDEX',
            'option_prefix': 'MIDCPNIFTY',
            'strike_interval': 100,
            'lot_size': 50,
            'expiry_day': 1,  # Tuesday
            'expiry_type': 'monthly'
        }
    }

    # Month abbreviations for Fyers format
    MONTH_ABBR = {
        1: 'JAN', 2: 'FEB', 3: 'MAR', 4: 'APR', 5: 'MAY', 6: 'JUN',
        7: 'JUL', 8: 'AUG', 9: 'SEP', 10: 'OCT', 11: 'NOV', 12: 'DEC'
    }

    def __init__(self, client_id: str, access_token: str):
        """
        Initialize symbol generator with Fyers API credentials

        Args:
            client_id: Fyers API client ID
            access_token: Valid Fyers access token
        """
        self.client_id = client_id
        self.access_token = access_token
        self.fyers = fyersModel.FyersModel(client_id=client_id, token=access_token)

    def get_spot_price(self, index_name: str) -> Optional[float]:
        """
        Fetch current spot price for an index

        Args:
            index_name: Index name (NIFTY, BANKNIFTY, FINNIFTY, MIDCPNIFTY)

        Returns:
            Current spot price or None if failed
        """
        try:
            config = self.INDEX_CONFIG.get(index_name)
            if not config:
                logger.error(f"Unknown index: {index_name}")
                return None

            spot_symbol = config['spot_symbol']

            # Fetch quote using Fyers API v3
            data = {
                "symbols": spot_symbol
            }

            response = self.fyers.quotes(data)

            if response and response.get('s') == 'ok':
                quote_data = response.get('d', [])
                if quote_data:
                    ltp = quote_data[0].get('v', {}).get('lp')
                    if ltp:
                        logger.info(f"{index_name} spot price: {ltp}")
                        return float(ltp)

            logger.error(f"Failed to fetch spot price for {index_name}: {response}")
            return None

        except Exception as e:
            logger.error(f"Error fetching spot price for {index_name}: {e}")
            return None

    def calculate_atm_strike(self, spot_price: float, strike_interval: int) -> int:
        """
        Calculate ATM strike price based on spot price

        Args:
            spot_price: Current spot price
            strike_interval: Strike interval (50 for NIFTY, 100 for BANKNIFTY)

        Returns:
            ATM strike price
        """
        # Round to nearest strike interval
        atm_strike = round(spot_price / strike_interval) * strike_interval
        return int(atm_strike)

    def get_next_expiry(self, index_name: str, expiry_type: str = 'weekly') -> Optional[datetime]:
        """
        Get next expiry date for an index

        Args:
            index_name: Index name
            expiry_type: 'weekly' or 'monthly'

        Returns:
            Next expiry datetime or None
        """
        try:
            config = self.INDEX_CONFIG.get(index_name)
            if not config:
                return None

            today = datetime.now()

            # Get monthly expiry (last Thursday) for reference
            monthly_expiry = self._get_monthly_expiry(today)

            if expiry_type == 'monthly':
                return monthly_expiry

            else:  # weekly
                expiry_day = config['expiry_day']  # 0=Monday, 1=Tuesday, etc.

                # Find next weekly expiry day
                days_ahead = expiry_day - today.weekday()
                if days_ahead <= 0:  # Target day already happened this week
                    days_ahead += 7

                next_weekly_expiry = today + timedelta(days=days_ahead)
                next_weekly_expiry = next_weekly_expiry.replace(hour=15, minute=30, second=0, microsecond=0)

                # CRITICAL: For NIFTY weekly options, check if this week contains monthly expiry
                if index_name == 'NIFTY':
                    # If the upcoming Tuesday is in the same week as monthly expiry (last Thursday)
                    # OR if the Tuesday comes after monthly expiry in the last week
                    # Use the monthly expiry instead

                    # Get the Monday of the week containing monthly expiry
                    monthly_week_start = monthly_expiry - timedelta(days=monthly_expiry.weekday())
                    monthly_week_end = monthly_week_start + timedelta(days=6)

                    # Check if our weekly expiry falls in the monthly expiry week
                    if monthly_week_start <= next_weekly_expiry <= monthly_week_end:
                        logger.info(f"NIFTY weekly expiry {next_weekly_expiry.date()} falls in monthly expiry week - using monthly expiry {monthly_expiry.date()}")
                        return monthly_expiry

                return next_weekly_expiry

        except Exception as e:
            logger.error(f"Error calculating expiry date: {e}")
            return None

    def _get_monthly_expiry(self, reference_date: datetime) -> datetime:
        """
        Calculate monthly expiry (last Thursday of the month)

        Args:
            reference_date: Reference date to calculate from

        Returns:
            Monthly expiry datetime
        """
        # Get last day of current month
        last_day = calendar.monthrange(reference_date.year, reference_date.month)[1]
        last_date = datetime(reference_date.year, reference_date.month, last_day)

        # Find last Thursday
        while last_date.weekday() != 1:  # 1 = Tuesday
            last_date -= timedelta(days=1)

        # If today is past monthly expiry, get next month's
        if reference_date.date() > last_date.date():
            next_month = reference_date.month + 1 if reference_date.month < 12 else 1
            next_year = reference_date.year if reference_date.month < 12 else reference_date.year + 1
            last_day = calendar.monthrange(next_year, next_month)[1]
            last_date = datetime(next_year, next_month, last_day)
            while last_date.weekday() != 3:
                last_date -= timedelta(days=1)

        return last_date.replace(hour=15, minute=30, second=0, microsecond=0)

    def format_symbol(self, index_name: str, expiry_date: datetime, strike: int, option_type: str) -> str:
        """
        Format option symbol according to Fyers symbology

        Format: NSE:UNDERLYING[YY][MMM/D][DD]STRIKEPRICE[CE/PE]

        Args:
            index_name: Index name (NIFTY, BANKNIFTY, etc.)
            expiry_date: Expiry date
            strike: Strike price
            option_type: 'CE' for Call, 'PE' for Put

        Returns:
            Formatted symbol string
        """
        try:
            config = self.INDEX_CONFIG.get(index_name)
            prefix = config['option_prefix']

            year = str(expiry_date.year)[2:]  # Last 2 digits of year
            month = self.MONTH_ABBR[expiry_date.month]
            day = f"{expiry_date.day:02d}"

            # Check if it's monthly expiry (last Thursday of month)
            last_day = calendar.monthrange(expiry_date.year, expiry_date.month)[1]
            last_date = datetime(expiry_date.year, expiry_date.month, last_day)
            while last_date.weekday() != 1:  # Find last Tuesday
                last_date -= timedelta(days=1)

            is_monthly = expiry_date.date() == last_date.date()

            if is_monthly:
                # Monthly format: NIFTY25DEC26000CE
                symbol = f"NSE:{prefix}{year}{month}{strike}{option_type}"
            else:
                # Weekly format: NIFTY25D1226000CE
                # Single character month mapping for weekly expiries
                month_char_map = {
                    1: '1', 2: '2', 3: '3', 4: '4', 5: '5', 6: '6',
                    7: '7', 8: '8', 9: '9', 10: 'O', 11: 'N', 12: 'D'
                }
                month_char = month_char_map[expiry_date.month]
                symbol = f"NSE:{prefix}{year}{month_char}{day}{strike}{option_type}"

            return symbol

        except Exception as e:
            logger.error(f"Error formatting symbol: {e}")
            return ""

    def generate_atm_symbols(
            self,
            indices: List[str] = None,
            num_strikes_otm: int = 0,
            include_spot: bool = False
    ) -> Dict[str, List[str]]:
        """
        Generate ATM option symbols for specified indices

        Args:
            indices: List of index names. If None, generates for all configured indices
            num_strikes_otm: Number of OTM strikes to include on each side (0 for ATM only)
            include_spot: Whether to include spot index symbols

        Returns:
            Dictionary mapping index names to list of symbols
        """
        if indices is None:
            indices = list(self.INDEX_CONFIG.keys())

        all_symbols = {}

        for index_name in indices:
            try:
                logger.info(f"Generating symbols for {index_name}...")

                config = self.INDEX_CONFIG[index_name]

                # Get spot price
                spot_price = self.get_spot_price(index_name)
                if not spot_price:
                    logger.error(f"Could not fetch spot price for {index_name}")
                    continue

                # Calculate ATM strike
                atm_strike = self.calculate_atm_strike(spot_price, config['strike_interval'])
                logger.info(f"{index_name} ATM Strike: {atm_strike} (Spot: {spot_price})")

                # Get next expiry
                expiry_date = self.get_next_expiry(index_name, config['expiry_type'])
                if not expiry_date:
                    logger.error(f"Could not determine expiry for {index_name}")
                    continue

                logger.info(f"{index_name} Next Expiry: {expiry_date.strftime('%Y-%m-%d %A')}")

                # Generate symbols
                symbols = []

                # Add spot symbol if requested
                if include_spot:
                    symbols.append(config['spot_symbol'])

                # Generate strikes (ATM + OTM on both sides)
                strike_range = range(
                    atm_strike - (num_strikes_otm * config['strike_interval']),
                    atm_strike + (num_strikes_otm * config['strike_interval']) + 1,
                    config['strike_interval']
                )

                for strike in strike_range:
                    # Generate CE (Call) symbol
                    ce_symbol = self.format_symbol(index_name, expiry_date, strike, 'CE')
                    if ce_symbol:
                        symbols.append(ce_symbol)

                    # Generate PE (Put) symbol
                    pe_symbol = self.format_symbol(index_name, expiry_date, strike, 'PE')
                    if pe_symbol:
                        symbols.append(pe_symbol)

                all_symbols[index_name] = symbols
                logger.info(f"Generated {len(symbols)} symbols for {index_name}")

                # Print samples
                logger.info(f"  Sample ATM symbols:")
                for sym in symbols[:4]:  # Show first 4 (2 CE + 2 PE if ATM only)
                    logger.info(f"    {sym}")

            except Exception as e:
                logger.error(f"Error generating symbols for {index_name}: {e}")
                continue

        return all_symbols

    def get_all_atm_symbols_flat(
            self,
            indices: List[str] = None,
            num_strikes_otm: int = 0,
            include_spot: bool = False
    ) -> List[str]:
        """
        Get all ATM symbols as a flat list (for direct use in streaming)

        Args:
            indices: List of index names
            num_strikes_otm: Number of OTM strikes on each side
            include_spot: Whether to include spot symbols

        Returns:
            Flat list of all symbols
        """
        symbols_dict = self.generate_atm_symbols(indices, num_strikes_otm, include_spot)

        # Flatten all symbols into single list
        all_symbols = []
        for index_name, symbols in symbols_dict.items():
            all_symbols.extend(symbols)

        return all_symbols

    def generate_custom_strikes(
            self,
            index_name: str,
            strikes: List[int],
            expiry_date: datetime = None
    ) -> List[str]:
        """
        Generate symbols for custom strike prices

        Args:
            index_name: Index name
            strikes: List of strike prices
            expiry_date: Expiry date (if None, uses next expiry)

        Returns:
            List of symbols
        """
        try:
            if expiry_date is None:
                config = self.INDEX_CONFIG[index_name]
                expiry_date = self.get_next_expiry(index_name, config['expiry_type'])

            if not expiry_date:
                return []

            symbols = []
            for strike in strikes:
                ce_symbol = self.format_symbol(index_name, expiry_date, strike, 'CE')
                pe_symbol = self.format_symbol(index_name, expiry_date, strike, 'PE')

                if ce_symbol:
                    symbols.append(ce_symbol)
                if pe_symbol:
                    symbols.append(pe_symbol)

            return symbols

        except Exception as e:
            logger.error(f"Error generating custom strikes: {e}")
            return []


def test_symbol_generator(client_id: str, access_token: str):
    """Test the symbol generator with sample data"""
    print("\n" + "=" * 80)
    print("ATM OPTION SYMBOL GENERATOR TEST")
    print("=" * 80)

    generator = ATMSymbolGenerator(client_id, access_token)

    # Test 1: Generate ATM symbols for all indices
    print("\n[Test 1] Generating ATM symbols for all indices...")
    symbols_dict = generator.generate_atm_symbols()

    for index_name, symbols in symbols_dict.items():
        print(f"\n{index_name}:")
        print(f"  Total symbols: {len(symbols)}")
        print(f"  Symbols:")
        for sym in symbols:
            print(f"    - {sym}")

    # Test 2: Generate with OTM strikes
    print("\n[Test 2] Generating ATM + 2 OTM strikes on each side for NIFTY...")
    nifty_symbols = generator.generate_atm_symbols(
        indices=['NIFTY'],
        num_strikes_otm=2
    )

    print(f"\nNIFTY with OTM strikes:")
    for sym in nifty_symbols['NIFTY']:
        print(f"  - {sym}")

    # Test 3: Get flat list for streaming
    print("\n[Test 3] Getting flat symbol list for streaming...")
    flat_symbols = generator.get_all_atm_symbols_flat(
        indices=['NIFTY', 'BANKNIFTY'],
        num_strikes_otm=1
    )

    print(f"\nFlat list ({len(flat_symbols)} symbols):")
    for sym in flat_symbols:
        print(f"  - {sym}")

    print("\n" + "=" * 80)


if __name__ == "__main__":
    import sys
    import os
    from dotenv import load_dotenv

    load_dotenv()

    client_id = os.environ.get('FYERS_CLIENT_ID')
    access_token = os.environ.get('FYERS_ACCESS_TOKEN')

    if not client_id or not access_token:
        print("Error: FYERS_CLIENT_ID and FYERS_ACCESS_TOKEN required in .env")
        sys.exit(1)

    test_symbol_generator(client_id, access_token)