import sqlite3
import json
import logging
import threading
import time
import os
import hashlib
import requests
import getpass
import sys
from datetime import datetime, timedelta
import queue
from fyers_apiv3 import fyersModel
from fyers_apiv3.FyersWebsocket import data_ws
import pandas as pd
from typing import Dict, List, Optional, Tuple
from dotenv import load_dotenv

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


class FyersAuthManager:
    """Enhanced Fyers authentication manager with refresh token and PIN support"""

    def __init__(self):
        self.client_id = os.environ.get('FYERS_CLIENT_ID')
        self.secret_key = os.environ.get('FYERS_SECRET_KEY')
        self.redirect_uri = os.environ.get('FYERS_REDIRECT_URI', "https://trade.fyers.in/api-login/redirect-to-app")
        self.refresh_token = os.environ.get('FYERS_REFRESH_TOKEN')
        self.access_token = os.environ.get('FYERS_ACCESS_TOKEN')
        self.pin = os.environ.get('FYERS_PIN')

    def save_to_env(self, key: str, value: str) -> None:
        """Save or update environment variable in .env file"""
        env_file = '.env'

        # Read existing .env file
        env_vars = {}
        if os.path.exists(env_file):
            with open(env_file, 'r') as f:
                for line in f:
                    if '=' in line and not line.strip().startswith('#'):
                        k, v = line.strip().split('=', 1)
                        env_vars[k] = v

        # Update the specific key
        env_vars[key] = value

        # Write back to .env file
        with open(env_file, 'w') as f:
            for k, v in env_vars.items():
                f.write(f"{k}={v}\n")

        # Update current environment
        os.environ[key] = value

    def _secure_input(self, prompt: str) -> str:
        """Get secure input with fallback to regular input"""
        try:
            # Try getpass first (more secure)
            return getpass.getpass(prompt).strip()
        except Exception:
            # Fallback to regular input if getpass fails
            print("Warning: Input will be visible on screen")
            return input(prompt.replace(":", " (visible): ")).strip()

    def get_or_request_pin(self) -> str:
        """Get PIN from environment or request from user"""
        if self.pin:
            return self.pin

        print("\n=== PIN Required for Token Refresh ===")
        print("Your trading PIN is required for security authentication.")

        pin = self._secure_input("Enter your Fyers trading PIN: ")

        if pin and pin.isdigit() and len(pin) >= 4:
            self.save_to_env('FYERS_PIN', pin)
            self.pin = pin
            return pin
        else:
            raise ValueError("Valid PIN is required for authentication")

    def get_app_id_hash(self) -> str:
        """Generate app_id_hash for API calls"""
        app_id = f"{self.client_id}:{self.secret_key}"
        return hashlib.sha256(app_id.encode()).hexdigest()

    def generate_access_token_with_refresh(self, refresh_token: str) -> Tuple[Optional[str], Optional[str]]:
        """Generate new access token using refresh token with PIN verification"""
        url = "https://api-t1.fyers.in/api/v3/validate-refresh-token"

        try:
            pin = self.get_or_request_pin()
        except ValueError as e:
            logger.error(f"PIN error: {e}")
            return None, None

        headers = {"Content-Type": "application/json"}
        data = {
            "grant_type": "refresh_token",
            "appIdHash": self.get_app_id_hash(),
            "refresh_token": refresh_token,
            "pin": pin
        }

        try:
            response = requests.post(url, headers=headers, data=json.dumps(data))
            response_data = response.json()

            if response_data.get('s') == 'ok' and 'access_token' in response_data:
                logger.info("Successfully refreshed access token")
                return response_data['access_token'], response_data.get('refresh_token')
            else:
                error_msg = response_data.get('message', 'Unknown error')
                logger.error(f"Error refreshing token: {error_msg}")
                return None, None

        except Exception as e:
            logger.error(f"Error while refreshing token: {e}")
            return None, None

    def get_tokens_from_auth_code(self, auth_code: str) -> Tuple[Optional[str], Optional[str]]:
        """Get both access and refresh tokens from auth code"""
        url = "https://api-t1.fyers.in/api/v3/validate-authcode"

        headers = {"Content-Type": "application/json"}
        data = {
            "grant_type": "authorization_code",
            "appIdHash": self.get_app_id_hash(),
            "code": auth_code
        }

        try:
            response = requests.post(url, headers=headers, data=json.dumps(data))
            response_data = response.json()

            if response_data.get('s') == 'ok':
                return (response_data.get('access_token'), response_data.get('refresh_token'))
            else:
                logger.error(f"Error getting tokens: {response_data.get('message', 'Unknown error')}")
                return None, None

        except Exception as e:
            logger.error(f"Exception while getting tokens: {e}")
            return None, None

    def is_token_valid(self, access_token: str) -> bool:
        """Check if access token is still valid"""
        if not access_token:
            return False

        try:
            url = "https://api-t1.fyers.in/api/v3/profile"
            headers = {'Authorization': f"{self.client_id}:{access_token}"}

            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                result = response.json()
                return result.get('s') == 'ok'
            return False
        except:
            return False

    def get_valid_access_token(self) -> Optional[str]:
        """Get a valid access token, using refresh token if available"""
        # First, check if current access token is still valid
        if self.access_token and self.is_token_valid(self.access_token):
            logger.info("Current access token is still valid")
            return self.access_token

        # Try to use refresh token if available
        if self.refresh_token:
            logger.info("Access token expired, trying to refresh...")
            new_access_token, new_refresh_token = self.generate_access_token_with_refresh(self.refresh_token)

            if new_access_token:
                logger.info("Successfully refreshed access token")
                self.save_to_env('FYERS_ACCESS_TOKEN', new_access_token)
                self.access_token = new_access_token

                if new_refresh_token:
                    self.save_to_env('FYERS_REFRESH_TOKEN', new_refresh_token)
                    self.refresh_token = new_refresh_token

                return new_access_token

        # If refresh failed or no refresh token, need manual authentication
        logger.error("Need to run authentication setup")
        return None

    def generate_auth_url(self) -> str:
        """Generate authorization URL"""
        auth_url = "https://api-t1.fyers.in/api/v3/generate-authcode"
        params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'response_type': 'code',
            'state': 'sample_state'
        }
        return f"{auth_url}?" + "&".join([f"{k}={v}" for k, v in params.items()])

    def setup_authentication(self) -> Optional[str]:
        """Setup authentication interactively"""
        print("\n=== Fyers API Authentication Setup ===")

        if not all([self.client_id, self.secret_key]):
            print("Missing CLIENT_ID or SECRET_KEY in environment variables")
            return None

        # Generate auth URL
        auth_url = self.generate_auth_url()
        print(f"\n1. Open this URL: {auth_url}")
        print("2. Complete authorization and get the code")

        auth_code = input("\nEnter authorization code: ").strip()

        # Get tokens
        access_token, refresh_token = self.get_tokens_from_auth_code(auth_code)

        if access_token:
            # Save tokens
            self.save_to_env('FYERS_ACCESS_TOKEN', access_token)
            if refresh_token:
                self.save_to_env('FYERS_REFRESH_TOKEN', refresh_token)

            print(f"\nAuthentication successful!")
            return access_token
        else:
            print("Authentication failed!")
            return None


class FyersDataStreamerV3:
    def __init__(self, client_id: str, access_token: str, db_path: str = "fyers_market_data.db"):
        """
        Initialize Fyers Data Streamer with API v3

        Args:
            client_id: Your Fyers client ID
            access_token: Your Fyers access token
            db_path: Path to SQLite database file
        """
        self.client_id = client_id
        self.access_token = access_token
        self.db_path = db_path

        # Initialize Fyers API v3 model
        self.fyers = fyersModel.FyersModel(client_id=client_id, token=access_token)

        # Connection state
        self.is_connected = False
        self.reconnect_count = 0

        # Data queue for thread-safe operations
        self.data_queue = queue.Queue(maxsize=10000)
        self.running = False

        # WebSocket connection
        self.websocket = None

        # Database connection
        self.setup_database()

        # Statistics tracking
        self.stats = {
            'messages_received': 0,
            'messages_saved': 0,
            'errors': 0,
            'start_time': None,
            'connection_status': 'disconnected'
        }

        # Symbol mapping for easier access
        self.symbol_mapping = {}

    def setup_database(self):
        """Create SQLite database and tables"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Create market data table with v3 API fields
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS market_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    symbol TEXT NOT NULL,
                    token INTEGER,
                    ltp REAL,
                    open_price REAL,
                    high_price REAL,
                    low_price REAL,
                    close_price REAL,
                    prev_close REAL,
                    volume INTEGER,
                    total_traded_value REAL,
                    bid_price REAL,
                    ask_price REAL,
                    bid_size INTEGER,
                    ask_size INTEGER,
                    total_buy_qty INTEGER,
                    total_sell_qty INTEGER,
                    avg_price REAL,
                    lower_circuit REAL,
                    upper_circuit REAL,
                    exchange TEXT,
                    segment TEXT,
                    oi REAL,
                    oi_change REAL,
                    price_change REAL,
                    price_change_percent REAL,
                    raw_data TEXT
                )
            ''')

            # Create depth data table for Level 2 data
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS market_depth (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    symbol TEXT NOT NULL,
                    token INTEGER,
                    bid_1_price REAL, bid_1_qty INTEGER,
                    bid_2_price REAL, bid_2_qty INTEGER,
                    bid_3_price REAL, bid_3_qty INTEGER,
                    bid_4_price REAL, bid_4_qty INTEGER,
                    bid_5_price REAL, bid_5_qty INTEGER,
                    ask_1_price REAL, ask_1_qty INTEGER,
                    ask_2_price REAL, ask_2_qty INTEGER,
                    ask_3_price REAL, ask_3_qty INTEGER,
                    ask_4_price REAL, ask_4_qty INTEGER,
                    ask_5_price REAL, ask_5_qty INTEGER,
                    raw_data TEXT
                )
            ''')

            # Create indexes for better query performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_symbol_timestamp ON market_data (symbol, timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON market_data (timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_symbol ON market_data (symbol)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_token ON market_data (token)')

            cursor.execute('CREATE INDEX IF NOT EXISTS idx_depth_symbol_timestamp ON market_depth (symbol, timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_depth_token ON market_depth (token)')

            # Create metadata table for tracking sessions
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS streaming_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE,
                    start_time TEXT,
                    end_time TEXT,
                    symbols_count INTEGER,
                    messages_received INTEGER,
                    messages_saved INTEGER,
                    status TEXT,
                    api_version TEXT
                )
            ''')

            conn.commit()
            conn.close()
            logging.info(f"Database initialized: {self.db_path}")

        except Exception as e:
            logging.error(f"Database setup error: {e}")
            raise

    def on_message(self, message):
        """Handle incoming WebSocket messages from Fyers API v3"""
        try:
            self.stats['messages_received'] += 1

            # Fyers API v3 message format
            if message:
                # Add processing timestamp
                message['processing_timestamp'] = datetime.now().isoformat()

                # Add to queue for processing
                self.data_queue.put(message)

                if self.stats['messages_received'] % 100 == 0:
                    logging.info(f"Received {self.stats['messages_received']} messages")

        except Exception as e:
            logging.error(f"Error processing message: {e}")
            self.stats['errors'] += 1

    def on_error(self, error):
        """Handle WebSocket errors"""
        logging.error(f"WebSocket error: {error}")
        self.stats['errors'] += 1
        self.stats['connection_status'] = 'error'

    def on_close(self):
        """Handle WebSocket close"""
        logging.info("WebSocket connection closed")
        self.stats['connection_status'] = 'disconnected'

    def on_open(self):
        """Handle WebSocket open"""
        self.is_connected = True
        self.reconnect_count = 0
        logging.info("WebSocket connection opened")
        self.stats['connection_status'] = 'connected'

    def process_data_queue(self):
        """Process data from queue and save to database"""
        batch_size = 100
        batch_data = []

        while self.running:
            try:
                try:
                    data = self.data_queue.get(timeout=1)
                    batch_data.append(data)
                except queue.Empty:
                    if batch_data:
                        self.save_batch_to_db(batch_data)
                        batch_data = []
                    continue

                if len(batch_data) >= batch_size:
                    self.save_batch_to_db(batch_data)
                    batch_data = []

            except Exception as e:
                logging.error(f"Error in data processing thread: {e}")
                self.stats['errors'] += 1

        if batch_data:
            self.save_batch_to_db(batch_data)

    def save_batch_to_db(self, batch_data: List[Dict]):
        """Save batch of data to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            for data in batch_data:
                try:
                    if 'symbol' in data and 'ltp' in data:
                        self.save_market_data(cursor, data)
                    elif 'bids' in data and 'asks' in data:
                        self.save_depth_data(cursor, data)
                    else:
                        self.save_market_data(cursor, data)

                    self.stats['messages_saved'] += 1

                except Exception as e:
                    logging.error(f"Error saving individual record: {e}")
                    self.stats['errors'] += 1

            conn.commit()
            conn.close()

        except Exception as e:
            logging.error(f"Error saving batch to database: {e}")
            self.stats['errors'] += 1

    def save_market_data(self, cursor, data):
        """Save market data to database"""
        timestamp = data.get('processing_timestamp', datetime.now().isoformat())

        record = (
            timestamp,
            data.get('symbol', ''),
            data.get('token'),
            data.get('ltp'),
            data.get('open_price', data.get('open')),
            data.get('high_price', data.get('high')),
            data.get('low_price', data.get('low')),
            data.get('close_price', data.get('close')),
            data.get('prev_close'),
            data.get('volume', data.get('vol')),
            data.get('total_traded_value', data.get('ttv')),
            data.get('bid_price', data.get('bid')),
            data.get('ask_price', data.get('ask')),
            data.get('bid_size'),
            data.get('ask_size'),
            data.get('total_buy_qty'),
            data.get('total_sell_qty'),
            data.get('avg_price', data.get('avg')),
            data.get('lower_circuit', data.get('lower_ckt')),
            data.get('upper_circuit', data.get('upper_ckt')),
            data.get('exchange'),
            data.get('segment'),
            data.get('oi'),
            data.get('oi_change'),
            data.get('price_change', data.get('ch')),
            data.get('price_change_percent', data.get('chp')),
            json.dumps(data)
        )

        cursor.execute('''
            INSERT INTO market_data 
            (timestamp, symbol, token, ltp, open_price, high_price, low_price, close_price,
             prev_close, volume, total_traded_value, bid_price, ask_price, bid_size, ask_size,
             total_buy_qty, total_sell_qty, avg_price, lower_circuit, upper_circuit,
             exchange, segment, oi, oi_change, price_change, price_change_percent, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', record)

    def save_depth_data(self, cursor, data):
        """Save market depth data to database"""
        timestamp = data.get('processing_timestamp', datetime.now().isoformat())

        bids = data.get('bids', [])
        asks = data.get('asks', [])

        while len(bids) < 5:
            bids.append({'price': None, 'qty': None})
        while len(asks) < 5:
            asks.append({'price': None, 'qty': None})

        record = (
            timestamp,
            data.get('symbol', ''),
            data.get('token'),
            bids[0].get('price'), bids[0].get('qty'),
            bids[1].get('price'), bids[1].get('qty'),
            bids[2].get('price'), bids[2].get('qty'),
            bids[3].get('price'), bids[3].get('qty'),
            bids[4].get('price'), bids[4].get('qty'),
            asks[0].get('price'), asks[0].get('qty'),
            asks[1].get('price'), asks[1].get('qty'),
            asks[2].get('price'), asks[2].get('qty'),
            asks[3].get('price'), asks[3].get('qty'),
            asks[4].get('price'), asks[4].get('qty'),
            json.dumps(data)
        )

        cursor.execute('''
            INSERT INTO market_depth 
            (timestamp, symbol, token, bid_1_price, bid_1_qty, bid_2_price, bid_2_qty,
             bid_3_price, bid_3_qty, bid_4_price, bid_4_qty, bid_5_price, bid_5_qty,
             ask_1_price, ask_1_qty, ask_2_price, ask_2_qty, ask_3_price, ask_3_qty,
             ask_4_price, ask_4_qty, ask_5_price, ask_5_qty, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', record)

    def start_streaming(self, symbols: List[str], data_type: str = "SymbolUpdate"):
        """Start streaming data for given symbols using Fyers API v3"""
        try:
            self.running = True
            self.stats['start_time'] = datetime.now()

            session_id = f"session_v3_{int(time.time())}"
            self.create_session_record(session_id, symbols)

            processing_thread = threading.Thread(target=self.process_data_queue, daemon=True)
            processing_thread.start()
            logging.info("Data processing thread started")

            self.websocket = data_ws.FyersDataSocket(
                access_token=self.access_token,
                log_path="",
                litemode=False,
                write_to_file=False,
                reconnect=True,
                reconnect_retry=10,
                on_connect=self.on_open,
                on_close=self.on_close,
                on_error=self.on_error,
                on_message=self.on_message
            )

            self._start_connection_thread()

            while not self.is_connected:
                time.sleep(0.1)

            self.websocket.subscribe(symbols=symbols, data_type=data_type)
            logging.info(f"Subscribed to {len(symbols)} symbols: {symbols}")

            self.websocket.keep_running()

            return self.is_connected

        except Exception as e:
            logging.error(f"Error starting streaming: {e}")
            self.running = False
            raise

    def _start_connection_thread(self):
        """Start WebSocket connection in background thread"""

        def run_connection():
            try:
                self.websocket.connect()
            except Exception as e:
                logging.error(f"Connection thread error: {e}")

        connection_thread = threading.Thread(target=run_connection)
        connection_thread.daemon = True
        connection_thread.start()

    def create_session_record(self, session_id: str, symbols: List[str]):
        """Create a session record in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO streaming_sessions 
                (session_id, start_time, symbols_count, messages_received, messages_saved, status, api_version)
                VALUES (?, ?, ?, 0, 0, 'RUNNING', 'v3')
            ''', (session_id, datetime.now().isoformat(), len(symbols)))

            conn.commit()
            conn.close()
            logging.info(f"Session record created: {session_id}")

        except Exception as e:
            logging.error(f"Error creating session record: {e}")

    def stop_streaming(self):
        """Stop the streaming process"""
        self.running = False
        if self.websocket:
            self.websocket.close_connection()

        duration = datetime.now() - self.stats['start_time'] if self.stats['start_time'] else timedelta(0)
        logging.info(f"Streaming stopped. Statistics:")
        logging.info(f"  Duration: {duration}")
        logging.info(f"  Messages received: {self.stats['messages_received']}")
        logging.info(f"  Messages saved: {self.stats['messages_saved']}")
        logging.info(f"  Errors: {self.stats['errors']}")

    def get_historical_data(self, symbol: str, start_date: str, end_date: str) -> pd.DataFrame:
        """Retrieve historical data from database"""
        try:
            conn = sqlite3.connect(self.db_path)

            df = pd.read_sql_query('''
                SELECT timestamp, symbol, ltp, open_price, high_price, low_price, close_price,
                       volume, bid_price, ask_price, price_change, price_change_percent
                FROM market_data
                WHERE symbol = ? AND timestamp BETWEEN ? AND ?
                ORDER BY timestamp
            ''', conn, params=(symbol, start_date, end_date))

            conn.close()

            if not df.empty:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                df.set_index('timestamp', inplace=True)

            return df

        except Exception as e:
            logging.error(f"Error retrieving historical data: {e}")
            return pd.DataFrame()


def setup_authentication():
    """Setup Fyers authentication with enhanced features"""
    print("=== Fyers API Authentication Setup ===")

    # Check existing credentials
    if not os.environ.get('FYERS_CLIENT_ID'):
        client_id = input("Enter Fyers Client ID: ").strip()
        secret_key = input("Enter Fyers Secret Key: ").strip()

        # Save to .env file
        auth_manager = FyersAuthManager()
        auth_manager.save_to_env('FYERS_CLIENT_ID', client_id)
        auth_manager.save_to_env('FYERS_SECRET_KEY', secret_key)

        # Reload environment
        os.environ['FYERS_CLIENT_ID'] = client_id
        os.environ['FYERS_SECRET_KEY'] = secret_key

    auth_manager = FyersAuthManager()
    access_token = auth_manager.setup_authentication()

    if access_token:
        print("Authentication setup completed successfully!")
        return True
    else:
        print("Authentication setup failed!")
        return False


def main():
    """Main function with enhanced authentication"""

    if len(sys.argv) > 1:
        command = sys.argv[1].lower()

        if command == "auth":
            setup_authentication()
            return
        elif command == "test-auth":
            auth_manager = FyersAuthManager()
            token = auth_manager.get_valid_access_token()
            if token:
                print("Authentication test successful!")
            else:
                print("Authentication test failed!")
            return

    # Main streaming logic
    try:
        # Enhanced authentication
        auth_manager = FyersAuthManager()
        access_token = auth_manager.get_valid_access_token()

        if not access_token:
            print("Authentication failed. Please run: python script.py auth")
            return

        CLIENT_ID = os.environ.get('FYERS_CLIENT_ID')

        # Symbols to stream
        SYMBOLS = [
            "NSE:SBIN-EQ",
            "NSE:RELIANCE-EQ",
            "NSE:TCS-EQ",
            "NSE:INFY-EQ",
            "NSE:HDFCBANK-EQ"
        ]

        DB_PATH = "fyers_market_data_v3.db"

        # Initialize and run streamer
        streamer = FyersDataStreamerV3(CLIENT_ID, access_token, DB_PATH)

        logging.info("Starting Fyers API v3 data streaming with enhanced authentication...")
        logging.info(f"Symbols: {SYMBOLS}")
        logging.info(f"Database: {DB_PATH}")

        streamer.start_streaming(SYMBOLS, data_type="SymbolUpdate")

    except KeyboardInterrupt:
        logging.info("Received interrupt signal, stopping...")
        if 'streamer' in locals():
            streamer.stop_streaming()

    except Exception as e:
        logging.error(f"Application error: {e}")
        if 'streamer' in locals():
            streamer.stop_streaming()


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Fyers Data Streaming with Enhanced Authentication")
        print("=" * 50)
        print("1. Setup Authentication")
        print("2. Test Authentication")
        print("3. Start Streaming")
        print("4. Exit")

        choice = input("\nSelect option (1-4): ").strip()

        if choice == "1":
            setup_authentication()
        elif choice == "2":
            auth_manager = FyersAuthManager()
            token = auth_manager.get_valid_access_token()
            if token:
                print("✅ Authentication test successful!")

                # Test API call
                try:
                    headers = {'Authorization': f"{os.environ.get('FYERS_CLIENT_ID')}:{token}"}
                    response = requests.get('https://api-t1.fyers.in/api/v3/profile', headers=headers)

                    if response.status_code == 200:
                        result = response.json()
                        if result.get('s') == 'ok':
                            profile = result.get('data', {})
                            print(f"Profile: {profile.get('name', 'Unknown')}")
                            print(f"Email: {profile.get('email', 'Unknown')}")
                        else:
                            print(f"API Error: {result.get('message')}")
                    else:
                        print(f"HTTP Error: {response.status_code}")
                except Exception as e:
                    print(f"API test error: {e}")
            else:
                print("❌ Authentication test failed!")
        elif choice == "3":
            main()
        elif choice == "4":
            print("Goodbye!")
        else:
            print("Invalid choice")
    else:
        main()