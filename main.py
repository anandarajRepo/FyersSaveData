"""
Complete Fyers Data Streaming Application with Automated ATM Symbol Generator
Merges original functionality with automatic option symbol generation

This is a drop-in replacement for your original main.py
"""

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

# Import symbol generator (must be in same directory)
try:
    from symbol_generator import ATMSymbolGenerator
    SYMBOL_GENERATOR_AVAILABLE = True
except ImportError:
    SYMBOL_GENERATOR_AVAILABLE = False
    logging.warning("symbol_generator.py not found - auto symbol generation disabled")

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

# Favorite stocks for tick data collection
FAVORITE_SYMBOLS = [
    "NSE:STLNETWORK-EQ",
    "NSE:STLTECH-EQ",
    "NSE:SKYGOLD-EQ",
]


class DatabaseManager:
    """Manages daily database files and operations"""

    def __init__(self, base_name: str = "fyers_market_data"):
        self.base_name = base_name
        self.db_directory = "data"
        self.ensure_directory_exists()

    def ensure_directory_exists(self):
        """Create data directory if it doesn't exist"""
        if not os.path.exists(self.db_directory):
            os.makedirs(self.db_directory)
            logger.info(f"Created database directory: {self.db_directory}")

    def get_daily_db_path(self, date: datetime = None) -> str:
        """Generate database path for a specific date"""
        if date is None:
            date = datetime.now()

        date_str = date.strftime("%Y%m%d")
        db_filename = f"{self.base_name}_{date_str}.db"
        return os.path.join(self.db_directory, db_filename)

    def get_current_db_path(self) -> str:
        """Get database path for current date"""
        return self.get_daily_db_path()

    def list_available_databases(self) -> List[Tuple[str, str]]:
        """List all available database files with their dates"""
        databases = []
        if os.path.exists(self.db_directory):
            for file in os.listdir(self.db_directory):
                if file.startswith(self.base_name) and file.endswith('.db'):
                    try:
                        date_part = file.replace(self.base_name + '_', '').replace('.db', '')
                        date_obj = datetime.strptime(date_part, '%Y%m%d')
                        full_path = os.path.join(self.db_directory, file)
                        databases.append((date_obj.strftime('%Y-%m-%d'), full_path))
                    except ValueError:
                        continue

        return sorted(databases, key=lambda x: x[0], reverse=True)

    def cleanup_old_databases(self, keep_days: int = 30):
        """Remove database files older than specified days"""
        cutoff_date = datetime.now() - timedelta(days=keep_days)
        removed_count = 0

        if os.path.exists(self.db_directory):
            for file in os.listdir(self.db_directory):
                if file.startswith(self.base_name) and file.endswith('.db'):
                    try:
                        date_part = file.replace(self.base_name + '_', '').replace('.db', '')
                        file_date = datetime.strptime(date_part, '%Y%m%d')

                        if file_date < cutoff_date:
                            file_path = os.path.join(self.db_directory, file)
                            os.remove(file_path)
                            removed_count += 1
                            logger.info(f"Removed old database: {file}")

                    except (ValueError, OSError) as e:
                        logger.error(f"Error processing file {file}: {e}")

        if removed_count > 0:
            logger.info(f"Cleanup completed: removed {removed_count} old database files")

        return removed_count


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
        """Get secure input with multiple fallback methods"""
        try:
            if (sys.stdin.isatty() and
                    not any(env in os.environ for env in ['JUPYTER_RUNTIME_DIR', 'VSCODE_PID', 'PYCHARM_HOSTED']) and
                    os.environ.get('TERM_PROGRAM') != 'vscode'):
                return getpass.getpass(prompt).strip()
        except Exception as e:
            print(f"Secure input method failed: {e}")

        print("⚠️ Note: PIN will be visible on screen (secure input not available in this environment)")
        return input(prompt.replace(":", " (visible): ")).strip()

    def _simple_input(self, prompt: str) -> str:
        """Simple visible input method"""
        print("ℹ️ Using simple input mode")
        return input(prompt).strip()

    def get_or_request_pin(self) -> str:
        """Get PIN from environment or request from user"""
        if self.pin:
            return self.pin

        print("\n" + "=" * 50)
        print("PIN REQUIRED FOR TOKEN REFRESH")
        print("=" * 50)
        print("Your trading PIN is required for security authentication.")
        print("This PIN will be saved in your .env file for future use.")

        max_attempts = 3
        for attempt in range(max_attempts):
            print(f"\nAttempt {attempt + 1}/{max_attempts}")

            print("\nChoose input method:")
            print("1. Secure input (PIN hidden) - Recommended")
            print("2. Simple input (PIN visible) - If option 1 doesn't work")

            choice = input("Select method (1/2) [default: 1]: ").strip()

            if choice == "2":
                pin = self._simple_input("Enter your Fyers trading PIN: ")
            else:
                pin = self._secure_input("Enter your Fyers trading PIN: ")

            if pin:
                if not pin.isdigit():
                    print(" PIN must contain only numbers")
                    continue

                if len(pin) < 4:
                    print(" PIN must be at least 4 digits")
                    continue

                try:
                    self.save_to_env('FYERS_PIN', pin)
                    self.pin = pin
                    print(" PIN saved successfully!")
                    return pin
                except Exception as e:
                    print(f" Error saving PIN: {e}")
                    continue
            else:
                print(" PIN cannot be empty")

        raise ValueError("PIN is required for authentication - max attempts exceeded")

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

                if 'pin' in error_msg.lower() or 'invalid pin' in error_msg.lower():
                    print(f"\n PIN Error: {error_msg}")
                    print("The saved PIN might be incorrect.")

                    self.pin = None
                    if 'FYERS_PIN' in os.environ:
                        del os.environ['FYERS_PIN']

                    retry = input("Would you like to retry with a new PIN? (y/n): ").strip().lower()
                    if retry == 'y':
                        return self.generate_access_token_with_refresh(refresh_token)

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
        if self.access_token and self.is_token_valid(self.access_token):
            logger.info("Current access token is still valid")
            return self.access_token

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
        print("\n" + "=" * 60)
        print(" FYERS API AUTHENTICATION SETUP")
        print("=" * 60)

        if not all([self.client_id, self.secret_key]):
            print(" Missing CLIENT_ID or SECRET_KEY in environment variables")
            return None

        auth_url = self.generate_auth_url()
        print(f"\n📋 STEPS TO COMPLETE AUTHENTICATION:")
        print(f"  1️⃣ Copy and open this URL in your browser:")
        print(f"    {auth_url}")
        print(f"\n  2️⃣ Complete the login process on Fyers website")
        print(f"  3️⃣ Copy the authorization code from the redirect URL")

        print(f"\n" + "-" * 60)
        auth_code = input(" Enter authorization code: ").strip()

        if not auth_code:
            print(" No authorization code provided")
            return None

        print(f"\n⏳ Processing authentication...")
        access_token, refresh_token = self.get_tokens_from_auth_code(auth_code)

        if access_token:
            self.save_to_env('FYERS_ACCESS_TOKEN', access_token)
            if refresh_token:
                self.save_to_env('FYERS_REFRESH_TOKEN', refresh_token)

            print(f"\n" + "=" * 60)
            print(f" AUTHENTICATION SUCCESSFUL!")
            print(f"=" * 60)
            print(f" Access Token: {access_token[:20]}...")
            if refresh_token:
                print(f"🔄 Refresh Token: {refresh_token[:20]}...")
            print(f"💾 Tokens saved to .env file")
            return access_token
        else:
            print(f"\n Authentication failed!")
            return None


class FyersDataStreamerV3:
    """Fyers Data Streamer with daily database support"""

    def __init__(self, client_id: str, access_token: str, db_manager: DatabaseManager = None):
        self.client_id = client_id
        self.access_token = access_token
        self.db_manager = db_manager if db_manager else DatabaseManager()

        self.fyers = fyersModel.FyersModel(client_id=client_id, token=access_token)

        self.is_connected = False
        self.reconnect_count = 0
        self.connection_lost_time = None
        self.last_message_time = None

        self.data_queue = queue.Queue(maxsize=10000)
        self.running = False

        self.websocket = None
        self.subscribed_symbols = []
        self.data_type = "SymbolUpdate"

        self.current_db_path = self.db_manager.get_current_db_path()
        self.current_date = datetime.now().date()

        self.setup_database()

        self.stats = {
            'messages_received': 0,
            'messages_saved': 0,
            'errors': 0,
            'start_time': None,
            'connection_status': 'disconnected',
            'current_db': self.current_db_path,
            'reconnections': 0,
            'last_reconnection': None
        }

        self.symbol_mapping = {}
        self.connection_lock = threading.Lock()

    def check_and_update_database(self):
        """Check if date has changed and update database accordingly"""
        current_date = datetime.now().date()

        if current_date != self.current_date:
            logger.info(f"Date changed from {self.current_date} to {current_date}")
            logger.info(f"Switching from database: {self.current_db_path}")

            self.current_date = current_date
            self.current_db_path = self.db_manager.get_current_db_path()
            self.stats['current_db'] = self.current_db_path

            self.setup_database()

            logger.info(f"Switched to new database: {self.current_db_path}")

            try:
                self.db_manager.cleanup_old_databases(keep_days=30)
            except Exception as e:
                logger.error(f"Error during database cleanup: {e}")

    def setup_database(self):
        """Create SQLite database and tables for current day"""
        try:
            logger.info(f"Setting up database: {self.current_db_path}")

            conn = sqlite3.connect(self.current_db_path)
            cursor = conn.cursor()

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

            cursor.execute('CREATE INDEX IF NOT EXISTS idx_symbol_timestamp ON market_data (symbol, timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON market_data (timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_symbol ON market_data (symbol)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_token ON market_data (token)')

            cursor.execute('CREATE INDEX IF NOT EXISTS idx_depth_symbol_timestamp ON market_depth (symbol, timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_depth_token ON market_depth (token)')

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
                    api_version TEXT,
                    trading_date TEXT
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS database_info (
                    created_date TEXT PRIMARY KEY,
                    creation_timestamp TEXT,
                    total_records INTEGER DEFAULT 0,
                    last_updated TEXT
                )
            ''')

            today_str = self.current_date.strftime('%Y-%m-%d')
            cursor.execute('''
                INSERT OR REPLACE INTO database_info 
                (created_date, creation_timestamp, last_updated)
                VALUES (?, ?, ?)
            ''', (today_str, datetime.now().isoformat(), datetime.now().isoformat()))

            conn.commit()
            conn.close()
            logger.info(f"Database initialized: {self.current_db_path}")

        except Exception as e:
            logger.error(f"Database setup error: {e}")
            raise

    def on_message(self, message):
        """Handle incoming WebSocket messages"""
        try:
            self.last_message_time = datetime.now()

            if self.stats['messages_received'] % 1000 == 0:
                self.check_and_update_database()

            self.stats['messages_received'] += 1

            if message:
                message['processing_timestamp'] = datetime.now().isoformat()

                try:
                    self.data_queue.put(message, timeout=1.0)
                except queue.Full:
                    logger.warning("Data queue is full, dropping message")
                    self.stats['errors'] += 1

                if self.stats['messages_received'] % 100 == 0:
                    logging.info(f"Received {self.stats['messages_received']} messages - DB: {os.path.basename(self.current_db_path)}")

        except Exception as e:
            logging.error(f"Error processing message: {e}")
            self.stats['errors'] += 1

    def on_error(self, error):
        """Handle WebSocket errors"""
        logging.error(f"WebSocket error: {error}")
        self.stats['errors'] += 1
        self.stats['connection_status'] = 'error'

        with self.connection_lock:
            if self.is_connected:
                self.connection_lost_time = datetime.now()
                self.is_connected = False

    def on_close(self):
        """Handle WebSocket close"""
        logging.info("WebSocket connection closed")
        self.stats['connection_status'] = 'disconnected'

        with self.connection_lock:
            if self.is_connected:
                self.connection_lost_time = datetime.now()
                self.is_connected = False

    def on_open(self):
        """Handle WebSocket open"""
        with self.connection_lock:
            was_reconnection = not self.is_connected and self.connection_lost_time is not None

            self.is_connected = True
            self.stats['connection_status'] = 'connected'

            if was_reconnection:
                self.stats['reconnections'] += 1
                self.stats['last_reconnection'] = datetime.now().isoformat()
                reconnect_duration = datetime.now() - self.connection_lost_time
                logging.info(f"WebSocket reconnected after {reconnect_duration.total_seconds():.1f} seconds")

                if self.subscribed_symbols:
                    logging.info(f"Re-subscribing to {len(self.subscribed_symbols)} symbols")
                    try:
                        time.sleep(0.5)
                        self.websocket.subscribe(symbols=self.subscribed_symbols, data_type=self.data_type)
                        logging.info("Successfully re-subscribed to symbols after reconnection")
                    except Exception as e:
                        logging.error(f"Failed to re-subscribe after reconnection: {e}")
                        threading.Timer(2.0, self._retry_subscription).start()
            else:
                logging.info("Initial WebSocket connection opened")

            self.connection_lost_time = None

    def _retry_subscription(self):
        """Retry subscription with exponential backoff"""
        max_retries = 3
        retry_count = 0

        while retry_count < max_retries and self.running:
            try:
                if self.is_connected and self.websocket:
                    logging.info(f"Retry {retry_count + 1}: Re-subscribing to symbols")
                    self.websocket.subscribe(symbols=self.subscribed_symbols, data_type=self.data_type)
                    logging.info("Successfully re-subscribed on retry")
                    return
            except Exception as e:
                logging.error(f"Retry {retry_count + 1} failed: {e}")

            retry_count += 1
            if retry_count < max_retries:
                delay = 2 ** retry_count
                time.sleep(delay)

        logging.error("Failed to re-subscribe after all retries")

    def process_data_queue(self):
        """Process data from queue and save to database"""
        batch_size = 100
        batch_data = []
        last_batch_time = time.time()
        batch_timeout = 5.0

        while self.running:
            try:
                try:
                    data = self.data_queue.get(timeout=1)
                    batch_data.append(data)
                    self.data_queue.task_done()
                except queue.Empty:
                    current_time = time.time()
                    if batch_data and (current_time - last_batch_time) > batch_timeout:
                        self.save_batch_to_db(batch_data)
                        batch_data = []
                        last_batch_time = current_time
                    continue

                if len(batch_data) >= batch_size:
                    self.save_batch_to_db(batch_data)
                    batch_data = []
                    last_batch_time = time.time()

            except Exception as e:
                logging.error(f"Error in data processing thread: {e}")
                self.stats['errors'] += 1

        if batch_data:
            self.save_batch_to_db(batch_data)

    def monitor_connection(self):
        """Monitor connection health"""
        check_interval = 30
        message_timeout = 60

        while self.running:
            try:
                time.sleep(check_interval)

                if not self.running:
                    break

                current_time = datetime.now()

                if (self.last_message_time and
                        (current_time - self.last_message_time).total_seconds() > message_timeout and
                        self.is_connected):
                    logging.warning(f"No messages received for {message_timeout} seconds")

                    logging.info(f"Current stats - Connected: {self.is_connected}, "
                                 f"Messages: {self.stats['messages_received']}, "
                                 f"Queue size: {self.data_queue.qsize()}")

                if self.stats['messages_received'] > 0:
                    messages_per_second = self.stats['messages_received'] / max(1, (current_time - self.stats['start_time']).total_seconds())
                    logging.info(f"Connection health - Messages/sec: {messages_per_second:.2f}, "
                                 f"Queue: {self.data_queue.qsize()}, "
                                 f"Reconnections: {self.stats['reconnections']}")

            except Exception as e:
                logging.error(f"Error in connection monitor: {e}")

    def save_batch_to_db(self, batch_data: List[Dict]):
        """Save batch of data to database"""
        try:
            conn = sqlite3.connect(self.current_db_path, timeout=10.0)
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
        """Start streaming data"""
        try:
            self.running = True
            self.stats['start_time'] = datetime.now()
            self.subscribed_symbols = symbols.copy()
            self.data_type = data_type

            session_id = f"session_v3_{int(time.time())}"
            self.create_session_record(session_id, symbols)

            processing_thread = threading.Thread(target=self.process_data_queue, daemon=True)
            processing_thread.start()
            logging.info("Data processing thread started")

            monitor_thread = threading.Thread(target=self.monitor_connection, daemon=True)
            monitor_thread.start()
            logging.info("Connection monitoring thread started")

            self.websocket = data_ws.FyersDataSocket(
                access_token=self.access_token,
                log_path="",
                litemode=False,
                write_to_file=False,
                reconnect=True,
                reconnect_retry=5,
                on_connect=self.on_open,
                on_close=self.on_close,
                on_error=self.on_error,
                on_message=self.on_message
            )

            self._start_connection_thread()

            connection_timeout = 30
            start_time = time.time()
            while not self.is_connected and (time.time() - start_time) < connection_timeout:
                time.sleep(0.1)

            if not self.is_connected:
                raise Exception("Failed to establish WebSocket connection within timeout")

            logging.info(f"Subscribing to {len(symbols)} symbols")
            self.websocket.subscribe(symbols=symbols, data_type=data_type)
            logging.info("Successfully subscribed to symbols")

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
                logging.info("Starting WebSocket connection...")
                self.websocket.connect()
            except Exception as e:
                logging.error(f"Connection thread error: {e}")
                self.stats['connection_status'] = 'error'

        connection_thread = threading.Thread(target=run_connection, daemon=True)
        connection_thread.start()

    def create_session_record(self, session_id: str, symbols: List[str]):
        """Create a session record"""
        try:
            conn = sqlite3.connect(self.current_db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO streaming_sessions 
                (session_id, start_time, symbols_count, messages_received, messages_saved, status, api_version, trading_date)
                VALUES (?, ?, ?, 0, 0, 'RUNNING', 'v3', ?)
            ''', (session_id, datetime.now().isoformat(), len(symbols), self.current_date.strftime('%Y-%m-%d')))

            conn.commit()
            conn.close()
            logging.info(f"Session record created: {session_id}")

        except Exception as e:
            logging.error(f"Error creating session record: {e}")

    def stop_streaming(self):
        """Stop streaming"""
        logging.info("Stopping streaming process...")
        self.running = False

        if self.websocket:
            try:
                self.websocket.close_connection()
            except Exception as e:
                logging.error(f"Error closing WebSocket: {e}")

        logging.info("Waiting for data queue to be processed...")
        try:
            self.data_queue.join()
        except Exception as e:
            logging.error(f"Error waiting for queue: {e}")

        duration = datetime.now() - self.stats['start_time'] if self.stats['start_time'] else timedelta(0)
        logging.info(f"Streaming stopped. Final Statistics:")
        logging.info(f"  Duration: {duration}")
        logging.info(f"  Messages received: {self.stats['messages_received']:,}")
        logging.info(f"  Messages saved: {self.stats['messages_saved']:,}")
        logging.info(f"  Errors: {self.stats['errors']:,}")
        logging.info(f"  Reconnections: {self.stats['reconnections']:,}")

    def get_historical_data(self, symbol: str, start_date: str, end_date: str, db_date: str = None) -> pd.DataFrame:
        """Retrieve historical data"""
        try:
            if db_date:
                db_path = self.db_manager.get_daily_db_path(datetime.strptime(db_date, '%Y-%m-%d'))
                if not os.path.exists(db_path):
                    logging.warning(f"Database for date {db_date} not found")
                    return pd.DataFrame()
            else:
                db_path = self.current_db_path

            conn = sqlite3.connect(db_path)

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

    def get_all_databases_summary(self) -> pd.DataFrame:
        """Get summary of all databases"""
        databases = self.db_manager.list_available_databases()
        summary_data = []

        for date_str, db_path in databases:
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()

                cursor.execute("SELECT COUNT(*) FROM market_data")
                record_count = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(DISTINCT symbol) FROM market_data")
                symbol_count = cursor.fetchone()[0]

                cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM market_data")
                time_range = cursor.fetchone()

                file_size = os.path.getsize(db_path) / (1024 * 1024)

                summary_data.append({
                    'date': date_str,
                    'database_file': os.path.basename(db_path),
                    'records': record_count,
                    'symbols': symbol_count,
                    'first_record': time_range[0] if time_range[0] else 'N/A',
                    'last_record': time_range[1] if time_range[1] else 'N/A',
                    'size_mb': round(file_size, 2)
                })

                conn.close()

            except Exception as e:
                logging.error(f"Error reading database {db_path}: {e}")
                summary_data.append({
                    'date': date_str,
                    'database_file': os.path.basename(db_path),
                    'records': 'Error',
                    'symbols': 'Error',
                    'first_record': 'Error',
                    'last_record': 'Error',
                    'size_mb': 'Error'
                })

        return pd.DataFrame(summary_data)


class SymbolManager:
    """Manages symbol generation and persistence"""

    def __init__(self, symbols_file: str = "daily_symbols.json"):
        self.symbols_file = symbols_file
        self.generator = None

    def initialize_generator(self, client_id: str, access_token: str):
        """Initialize the ATM symbol generator"""
        if not SYMBOL_GENERATOR_AVAILABLE:
            logger.warning("Symbol generator not available - using manual symbols")
            return False

        try:
            self.generator = ATMSymbolGenerator(client_id, access_token)
            logger.info("Symbol generator initialized")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize symbol generator: {e}")
            return False

    def generate_daily_symbols(
        self,
        indices: List[str] = None,
        num_strikes_otm: int = 1,
        include_spot: bool = False,
        save_to_file: bool = True
    ) -> List[str]:
        """Generate ATM symbols for the day"""
        if not self.generator:
            logger.error("Generator not initialized")
            return []

        try:
            logger.info("Generating daily ATM symbols...")

            if indices is None:
                indices = ['NIFTY', 'BANKNIFTY', 'FINNIFTY', 'MIDCPNIFTY']

            symbols = self.generator.get_all_atm_symbols_flat(
                indices=indices,
                num_strikes_otm=num_strikes_otm,
                include_spot=include_spot
            )

            logger.info(f"Generated {len(symbols)} symbols")

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
        """Save symbols to JSON file"""
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

    def load_favorite_symbols(self) -> List[str]:
        """Load favorite symbols from global FAVORITE_SYMBOLS constant"""
        if FAVORITE_SYMBOLS:
            logger.info(f"Loaded {len(FAVORITE_SYMBOLS)} favorite symbols: {FAVORITE_SYMBOLS}")
            return FAVORITE_SYMBOLS.copy()
        return []

    def get_or_generate_symbols(
        self,
        indices: List[str] = None,
        num_strikes_otm: int = 1,
        force_regenerate: bool = False,
        include_favorites: bool = True
    ) -> List[str]:
        """Get symbols - load from file if available for today, otherwise generate

        Args:
            indices: List of indices to generate symbols for
            num_strikes_otm: Number of strikes OTM to include
            force_regenerate: Force regeneration even if today's symbols exist
            include_favorites: Include favorite symbols from configuration

        Returns:
            Combined list of generated and favorite symbols
        """
        symbols = []

        # Load or generate option symbols
        if not force_regenerate:
            symbols = self.load_symbols_from_file()
            if not symbols:
                logger.info("Generating new symbols...")
                symbols = self.generate_daily_symbols(indices, num_strikes_otm)
        else:
            logger.info("Generating new symbols...")
            symbols = self.generate_daily_symbols(indices, num_strikes_otm)

        # Add favorite symbols if enabled
        if include_favorites:
            favorite_symbols = self.load_favorite_symbols()
            if favorite_symbols:
                symbols.extend(favorite_symbols)
                logger.info(f"Total symbols (including favorites): {len(symbols)}")

        return symbols


def setup_authentication():
    """Setup Fyers authentication"""
    print("\n" + "=" * 60)
    print(" FYERS API AUTHENTICATION SETUP")
    print("=" * 60)

    if not os.environ.get('FYERS_CLIENT_ID'):
        print("\n Enter your Fyers API credentials:")
        client_id = input("Fyers Client ID: ").strip()
        secret_key = input("Fyers Secret Key: ").strip()

        if not client_id or not secret_key:
            print(" Both Client ID and Secret Key are required!")
            return False

        auth_manager = FyersAuthManager()
        auth_manager.save_to_env('FYERS_CLIENT_ID', client_id)
        auth_manager.save_to_env('FYERS_SECRET_KEY', secret_key)

        os.environ['FYERS_CLIENT_ID'] = client_id
        os.environ['FYERS_SECRET_KEY'] = secret_key
        print(" Credentials saved to .env file")

    auth_manager = FyersAuthManager()
    access_token = auth_manager.setup_authentication()

    if access_token:
        print("\n Authentication setup completed successfully!")
        return True
    else:
        print("\n Authentication setup failed!")
        return False


def test_authentication():
    """Test authentication"""
    print("\n" + "=" * 60)
    print(" TESTING FYERS API AUTHENTICATION")
    print("=" * 60)

    auth_manager = FyersAuthManager()
    token = auth_manager.get_valid_access_token()

    if token:
        print(" Authentication successful!")
        print(f" Access Token: {token[:20]}...")

        try:
            print("\n Testing API connectivity...")
            headers = {'Authorization': f"{os.environ.get('FYERS_CLIENT_ID')}:{token}"}
            response = requests.get('https://api-t1.fyers.in/api/v3/profile', headers=headers)

            if response.status_code == 200:
                result = response.json()
                if result.get('s') == 'ok':
                    profile = result.get('data', {})
                    print(" API Connection successful!")
                    print(f"👤 Name: {profile.get('name', 'Unknown')}")
                    print(f" Email: {profile.get('email', 'Unknown')}")
                    print(f" User ID: {profile.get('id', 'Unknown')}")
                    return True
                else:
                    print(f" API Error: {result.get('message')}")
            else:
                print(f" HTTP Error: {response.status_code}")
        except Exception as e:
            print(f" API test error: {e}")

    else:
        print(" Authentication failed!")
        print(" Try running: python main.py auth")

    return False


def interactive_symbol_generator(client_id: str, access_token: str) -> List[str]:
    """Interactive symbol generation menu"""
    if not SYMBOL_GENERATOR_AVAILABLE:
        print("\n Symbol generator not available!")
        print(" Ensure symbol_generator.py is in the same directory")
        return []

    print("\n" + "=" * 80)
    print(" ATM OPTION SYMBOL GENERATOR")
    print("=" * 80)

    symbol_manager = SymbolManager()
    if not symbol_manager.initialize_generator(client_id, access_token):
        return []

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
            print("️ Invalid selection, using all indices")
            indices = ['NIFTY', 'BANKNIFTY', 'FINNIFTY', 'MIDCPNIFTY']

    print(f"\n Selected indices: {', '.join(indices)}")

    print("\n Number of OTM strikes on each side:")
    print("   0 = ATM only (2 symbols per index: 1 CE + 1 PE)")
    print("   1 = ATM + 1 OTM (6 symbols per index)")
    print("   2 = ATM + 2 OTM (10 symbols per index)")

    num_otm = input("\n Enter number [1]: ").strip()
    num_strikes_otm = int(num_otm) if num_otm.isdigit() else 1

    include_spot = input("\n Include spot index symbols? (y/n) [n]: ").strip().lower() == 'y'

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


def show_streaming_stats():
    """Show streaming statistics"""
    db_manager = DatabaseManager()
    current_db_path = db_manager.get_current_db_path()

    if not os.path.exists(current_db_path):
        print("️ No database found for today. Start streaming first.")
        return

    try:
        conn = sqlite3.connect(current_db_path)

        sessions_df = pd.read_sql_query('''
            SELECT session_id, start_time, symbols_count, messages_received, messages_saved, status, trading_date
            FROM streaming_sessions 
            ORDER BY start_time DESC 
            LIMIT 5
        ''', conn)

        data_stats = pd.read_sql_query('''
            SELECT 
                symbol,
                COUNT(*) as tick_count,
                MIN(timestamp) as first_tick,
                MAX(timestamp) as last_tick,
                AVG(volume) as avg_volume
            FROM market_data 
            GROUP BY symbol
            ORDER BY tick_count DESC
        ''', conn)

        conn.close()

        print("\n" + "=" * 60)
        print(f" STREAMING STATISTICS - {datetime.now().strftime('%Y-%m-%d')}")
        print("=" * 60)
        print(f" Current Database: {os.path.basename(current_db_path)}")

        if not sessions_df.empty:
            print("\n Recent Sessions:")
            for _, session in sessions_df.iterrows():
                print(f"   {session['start_time'][:19]} | "
                      f"Date: {session['trading_date']} | "
                      f"Symbols: {session['symbols_count']} | "
                      f"Messages: {session['messages_received']:,} | "
                      f"Status: {session['status']}")

        if not data_stats.empty:
            print(f"\n Data Summary:")
            print(f"{'Symbol':<20} {'Ticks':<10} {'First':<20} {'Last':<20}")
            print("-" * 70)
            for _, row in data_stats.head().iterrows():
                print(f"{row['symbol']:<20} {row['tick_count']:,<10} "
                      f"{row['first_tick'][:19]:<20} {row['last_tick'][:19]:<20}")
        else:
            print("️ No market data found for today.")

    except Exception as e:
        print(f" Error reading stats: {e}")


def show_database_summary():
    """Show database summary"""
    print("\n" + "=" * 60)
    print(" DATABASE SUMMARY")
    print("=" * 60)

    db_manager = DatabaseManager()

    try:
        streamer = FyersDataStreamerV3("dummy", "dummy", db_manager)
        summary_df = streamer.get_all_databases_summary()

        if not summary_df.empty:
            print(f"\n Found {len(summary_df)} database files:")
            print(f"{'Date':<12} {'File':<30} {'Records':<10} {'Symbols':<8} {'Size(MB)':<10}")
            print("-" * 80)

            total_records = 0
            total_size = 0

            for _, row in summary_df.iterrows():
                print(f"{row['date']:<12} {row['database_file']:<30} "
                      f"{row['records']:<10} {row['symbols']:<8} {row['size_mb']:<10}")

                if isinstance(row['records'], int):
                    total_records += row['records']
                if isinstance(row['size_mb'], (int, float)):
                    total_size += row['size_mb']

            print("-" * 80)
            print(f"{'TOTAL':<42} {total_records:,<10} {'':<8} {total_size:.2f}")

        else:
            print("️ No database files found.")

    except Exception as e:
        print(f" Error generating database summary: {e}")


def cleanup_old_databases():
    """Cleanup old databases"""
    print("\n" + "=" * 60)
    print("️ DATABASE CLEANUP")
    print("=" * 60)

    db_manager = DatabaseManager()

    try:
        databases = db_manager.list_available_databases()

        if not databases:
            print("️ No database files found.")
            return

        print(f" Found {len(databases)} database files:")
        for i, (date_str, db_path) in enumerate(databases[:10], 1):
            file_size = os.path.getsize(db_path) / (1024 * 1024)
            print(f"   {i:2d}. {date_str} - {os.path.basename(db_path)} ({file_size:.1f} MB)")

        if len(databases) > 10:
            print(f"   ... and {len(databases) - 10} more files")

        print(f"\n Options:")
        print(f"   1. Keep last 7 days")
        print(f"   2. Keep last 30 days")
        print(f"   3. Keep last 90 days")
        print(f"   4. Custom number of days")
        print(f"   5. Cancel")

        choice = input("\n Select option (1-5): ").strip()

        if choice == "1":
            keep_days = 7
        elif choice == "2":
            keep_days = 30
        elif choice == "3":
            keep_days = 90
        elif choice == "4":
            try:
                keep_days = int(input(" Enter number of days to keep: "))
                if keep_days < 1:
                    print(" Invalid number of days.")
                    return
            except ValueError:
                print(" Invalid input.")
                return
        elif choice == "5":
            print("️ Cleanup cancelled.")
            return
        else:
            print(" Invalid choice.")
            return

        cutoff_date = datetime.now() - timedelta(days=keep_days)
        files_to_remove = [
            (date_str, db_path) for date_str, db_path in databases
            if datetime.strptime(date_str, '%Y-%m-%d') < cutoff_date
        ]

        if not files_to_remove:
            print(f" No files older than {keep_days} days found.")
            return

        print(f"\n️ Files to be removed ({len(files_to_remove)} files):")
        total_size = 0
        for date_str, db_path in files_to_remove:
            file_size = os.path.getsize(db_path) / (1024 * 1024)
            total_size += file_size
            print(f"   {date_str} - {os.path.basename(db_path)} ({file_size:.1f} MB)")

        print(f"\n Total space to be freed: {total_size:.1f} MB")

        confirm = input(f"\n Proceed with cleanup? (y/N): ").strip().lower()
        if confirm == 'y':
            removed_count = db_manager.cleanup_old_databases(keep_days)
            print(f"\n Cleanup completed: removed {removed_count} files")
        else:
            print("️ Cleanup cancelled.")

    except Exception as e:
        print(f" Error during cleanup: {e}")


def update_pin():
    """Update trading PIN"""
    print("\n" + "=" * 60)
    print(" UPDATE TRADING PIN")
    print("=" * 60)

    auth_manager = FyersAuthManager()

    auth_manager.pin = None
    if 'FYERS_PIN' in os.environ:
        del os.environ['FYERS_PIN']

    try:
        pin = auth_manager.get_or_request_pin()
        if pin:
            print(" PIN updated successfully!")
        else:
            print(" PIN update failed!")
    except Exception as e:
        print(f" Error updating PIN: {e}")


def show_menu():
    """Display main menu"""
    print("\n" + "=" * 60)
    print("🚀 FYERS DATA STREAMING - ATM SYMBOL GENERATOR")
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


def main():
    """Main function"""

    if len(sys.argv) > 1:
        command = sys.argv[1].lower()

        if command == "auth":
            setup_authentication()
            return
        elif command == "test-auth":
            test_authentication()
            return
        elif command == "generate-symbols":
            auth_manager = FyersAuthManager()
            access_token = auth_manager.get_valid_access_token()
            if access_token:
                client_id = os.environ.get('FYERS_CLIENT_ID')
                interactive_symbol_generator(client_id, access_token)
            return
        elif command == "stream":
            pass  # Continue to streaming
        elif command == "cleanup":
            cleanup_old_databases()
            return
        else:
            print("Available commands:")
            print("  python main.py auth              - Setup authentication")
            print("  python main.py test-auth         - Test authentication")
            print("  python main.py generate-symbols  - Generate ATM symbols")
            print("  python main.py stream            - Start streaming (auto-generate)")
            print("  python main.py cleanup           - Cleanup old databases")
            print("  python main.py                   - Interactive menu")
            return

    # Interactive mode
    if len(sys.argv) == 1:
        use_auto_symbols = False
        use_saved_symbols = False

        while True:
            show_menu()
            choice = input(" Select option (1-10): ").strip()

            if choice == "1":
                setup_authentication()
            elif choice == "2":
                test_authentication()
            elif choice == "3":
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
                print("👋 Goodbye!")
                return
            else:
                print(" Invalid choice. Please select 1-10.")
    else:
        use_auto_symbols = True

    # Main streaming logic
    try:
        print("\n" + "=" * 60)
        print(" STARTING FYERS DATA STREAMING")
        print("=" * 60)

        auth_manager = FyersAuthManager()
        access_token = auth_manager.get_valid_access_token()

        if not access_token:
            print(" Authentication failed!")
            print(" Please run: python main.py auth")
            return

        CLIENT_ID = os.environ.get('FYERS_CLIENT_ID')

        # Symbol generation/loading
        symbol_manager = SymbolManager()

        if use_auto_symbols:
            if symbol_manager.initialize_generator(CLIENT_ID, access_token):
                print("\n Generating ATM symbols automatically...")
                SYMBOLS = symbol_manager.get_or_generate_symbols(
                    indices=['NIFTY', 'BANKNIFTY', 'FINNIFTY', 'MIDCPNIFTY'],
                    num_strikes_otm=0, # 0 - ATM only, 1 - ATM ±1, 2 - ATM ±2 - No. of options generation
                    force_regenerate=False
                )
            else:
                print("\n Symbol generator not available, using manual symbols")
                SYMBOLS = []
                # Load favorite symbols as fallback
                favorite_symbols = symbol_manager.load_favorite_symbols()
                if favorite_symbols:
                    SYMBOLS.extend(favorite_symbols)
        else:
            SYMBOLS = symbol_manager.load_symbols_from_file()
            if not SYMBOLS:
                print("\n️ No saved symbols found")
                if symbol_manager.initialize_generator(CLIENT_ID, access_token):
                    print(" Generating new symbols...")
                    SYMBOLS = symbol_manager.generate_daily_symbols()
                else:
                    SYMBOLS = []

            # Always add favorite symbols when using saved symbols
            favorite_symbols = symbol_manager.load_favorite_symbols()
            if favorite_symbols:
                SYMBOLS.extend(favorite_symbols)

        # Fallback to hardcoded symbols if generation failed
        # if not SYMBOLS:
        #     print("\n️ Using fallback hardcoded symbols")
        #     SYMBOLS = [
        #         "NSE:NIFTY25D1226000CE",
        #         "NSE:NIFTY25D1226000PE",
        #         "NSE:BANKNIFTY25D1158000CE",
        #         "NSE:BANKNIFTY25D1158000PE",
        #     ]

        db_manager = DatabaseManager()
        current_db_path = db_manager.get_current_db_path()

        print(f"\n Configuration:")
        print(f"   Client ID: {CLIENT_ID}")
        print(f"   Symbols: {len(SYMBOLS)}")
        print(f"   Database: {current_db_path}")
        print(f"   Trading Date: {datetime.now().strftime('%Y-%m-%d')}")

        print(f"\nSymbols to stream:")
        for sym in SYMBOLS:
            print(f"   - {sym}")

        # confirm = input("\nStart streaming? (y/n) [y]: ").strip().lower()
        # if confirm == 'n':
        #     print("️ Streaming cancelled")
        #     return

        streamer = FyersDataStreamerV3(CLIENT_ID, access_token, db_manager)

        print(f"\nInitializing WebSocket connection...")
        streamer.start_streaming(SYMBOLS, data_type="SymbolUpdate")

    except KeyboardInterrupt:
        print(f"\nReceived interrupt signal (Ctrl+C)")
        print(f"Stopping streaming gracefully...")
        if 'streamer' in locals():
            streamer.stop_streaming()
        print(f"Streaming stopped successfully!")
        print(f"Data saved to: {streamer.current_db_path}")

    except Exception as e:
        print(f"\n Application error: {e}")
        logging.error(f"Fatal application error: {e}", exc_info=True)
        if 'streamer' in locals():
            streamer.stop_streaming()


if __name__ == "__main__":
    main()