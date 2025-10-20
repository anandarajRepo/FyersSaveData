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


class DatabaseManager:
    """Manages daily database files and operations"""

    def __init__(self, base_name: str = "fyers_market_data"):
        self.base_name = base_name
        self.db_directory = "data"  # Directory to store database files
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
                    # Extract date from filename
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
        # Method 1: Try getpass (hidden input) only in proper terminals
        try:
            # Check if we're in an interactive terminal and not in IDE/notebook
            if (sys.stdin.isatty() and
                    not any(env in os.environ for env in ['JUPYTER_RUNTIME_DIR', 'VSCODE_PID', 'PYCHARM_HOSTED']) and
                    os.environ.get('TERM_PROGRAM') != 'vscode'):
                return getpass.getpass(prompt).strip()
        except Exception as e:
            print(f"Secure input method failed: {e}")

        # Method 2: Fallback to regular input with clear warning
        print(" Note: PIN will be visible on screen (secure input not available in this environment)")
        return input(prompt.replace(":", " (visible): ")).strip()

    def _simple_input(self, prompt: str) -> str:
        """Simple visible input method"""
        print(" Using simple input mode")
        return input(prompt).strip()

    def get_or_request_pin(self) -> str:
        """Get PIN from environment or request from user with better input handling"""
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

            # Give user choice of input method
            print("\nChoose input method:")
            print("1. Secure input (PIN hidden) - Recommended")
            print("2. Simple input (PIN visible) - If option 1 doesn't work")

            choice = input("Select method (1/2) [default: 1]: ").strip()

            if choice == "2":
                pin = self._simple_input("Enter your Fyers trading PIN: ")
            else:
                pin = self._secure_input("Enter your Fyers trading PIN: ")

            if pin:
                # Basic validation
                if not pin.isdigit():
                    print(" PIN must contain only numbers")
                    continue

                if len(pin) < 4:
                    print(" PIN must be at least 4 digits")
                    continue

                # Save PIN to environment for future use
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

                # Handle PIN-specific errors
                if 'pin' in error_msg.lower() or 'invalid pin' in error_msg.lower():
                    print(f"\n PIN Error: {error_msg}")
                    print("The saved PIN might be incorrect.")

                    # Clear saved PIN and retry
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
        print("\n" + "=" * 60)
        print(" FYERS API AUTHENTICATION SETUP")
        print("=" * 60)

        if not all([self.client_id, self.secret_key]):
            print(" Missing CLIENT_ID or SECRET_KEY in environment variables")
            return None

        # Generate auth URL
        auth_url = self.generate_auth_url()
        print(f"\n STEPS TO COMPLETE AUTHENTICATION:")
        print(f"  Copy and open this URL in your browser:")
        print(f"    {auth_url}")
        print(f"\n  Complete the login process on Fyers website")
        print(f"  Copy the authorization code from the redirect URL")

        print(f"\n" + "-" * 60)
        auth_code = input(" Enter authorization code: ").strip()

        if not auth_code:
            print(" No authorization code provided")
            return None

        print(f"\n Processing authentication...")
        # Get tokens
        access_token, refresh_token = self.get_tokens_from_auth_code(auth_code)

        if access_token:
            # Save tokens
            self.save_to_env('FYERS_ACCESS_TOKEN', access_token)
            if refresh_token:
                self.save_to_env('FYERS_REFRESH_TOKEN', refresh_token)

            print(f"\n" + "=" * 60)
            print(f" AUTHENTICATION SUCCESSFUL!")
            print(f"=" * 60)
            print(f" Access Token: {access_token[:20]}...")
            if refresh_token:
                print(f" Refresh Token: {refresh_token[:20]}...")
            print(f" Tokens saved to .env file")
            return access_token
        else:
            print(f"\n Authentication failed!")
            return None


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


class DatabaseManager:
    """Manages daily database files and operations"""

    def __init__(self, base_name: str = "fyers_market_data"):
        self.base_name = base_name
        self.db_directory = "data"  # Directory to store database files
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


class FyersDataStreamerV3:
    def __init__(self, client_id: str, access_token: str, db_manager: DatabaseManager = None):
        """
        Initialize Fyers Data Streamer with API v3 and daily database support
        """
        self.client_id = client_id
        self.access_token = access_token
        self.db_manager = db_manager if db_manager else DatabaseManager()

        # Initialize Fyers API v3 model
        self.fyers = fyersModel.FyersModel(client_id=client_id, token=access_token)

        # Connection state
        self.is_connected = False
        self.reconnect_count = 0
        self.connection_lost_time = None
        self.last_message_time = None

        # Data queue for thread-safe operations
        self.data_queue = queue.Queue(maxsize=10000)
        self.running = False

        # WebSocket connection
        self.websocket = None
        self.subscribed_symbols = []  # Track subscribed symbols
        self.data_type = "SymbolUpdate"  # Track data type

        # Current database path (changes daily)
        self.current_db_path = self.db_manager.get_current_db_path()
        self.current_date = datetime.now().date()

        # Setup database for current day
        self.setup_database()

        # Statistics tracking
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

        # Symbol mapping for easier access
        self.symbol_mapping = {}

        # Thread locks
        self.connection_lock = threading.Lock()

    def check_and_update_database(self):
        """Check if date has changed and update database accordingly"""
        current_date = datetime.now().date()

        if current_date != self.current_date:
            logger.info(f"Date changed from {self.current_date} to {current_date}")
            logger.info(f"Switching from database: {self.current_db_path}")

            # Update to new database
            self.current_date = current_date
            self.current_db_path = self.db_manager.get_current_db_path()
            self.stats['current_db'] = self.current_db_path

            # Setup new database
            self.setup_database()

            logger.info(f"Switched to new database: {self.current_db_path}")

            # Optional: Cleanup old databases (keep last 30 days)
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
                    api_version TEXT,
                    trading_date TEXT
                )
            ''')

            # Add database metadata
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS database_info (
                    created_date TEXT PRIMARY KEY,
                    creation_timestamp TEXT,
                    total_records INTEGER DEFAULT 0,
                    last_updated TEXT
                )
            ''')

            # Insert or update database info
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
        """Handle incoming WebSocket messages from Fyers API v3"""
        try:
            # Update last message time
            self.last_message_time = datetime.now()

            # Check if date has changed (at start of each message processing)
            if self.stats['messages_received'] % 1000 == 0:  # Check every 1000 messages
                self.check_and_update_database()

            self.stats['messages_received'] += 1

            # Fyers API v3 message format
            if message:
                # Add processing timestamp
                message['processing_timestamp'] = datetime.now().isoformat()

                # Add to queue for processing
                try:
                    self.data_queue.put(message, timeout=1.0)  # Add timeout to prevent blocking
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
        """Handle WebSocket open - FIXED RESUBSCRIPTION"""
        with self.connection_lock:
            was_reconnection = not self.is_connected and self.connection_lost_time is not None

            self.is_connected = True
            self.stats['connection_status'] = 'connected'

            if was_reconnection:
                self.stats['reconnections'] += 1
                self.stats['last_reconnection'] = datetime.now().isoformat()
                reconnect_duration = datetime.now() - self.connection_lost_time
                logging.info(f"WebSocket reconnected after {reconnect_duration.total_seconds():.1f} seconds")

                # CRITICAL FIX: Re-subscribe to symbols after reconnection
                if self.subscribed_symbols:
                    logging.info(f"Re-subscribing to {len(self.subscribed_symbols)} symbols: {self.subscribed_symbols}")
                    try:
                        # Add a small delay to ensure connection is fully established
                        time.sleep(0.5)
                        self.websocket.subscribe(symbols=self.subscribed_symbols, data_type=self.data_type)
                        logging.info("Successfully re-subscribed to symbols after reconnection")
                    except Exception as e:
                        logging.error(f"Failed to re-subscribe after reconnection: {e}")
                        # Try again after a longer delay
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
                delay = 2 ** retry_count  # Exponential backoff: 2, 4, 8 seconds
                time.sleep(delay)

        logging.error("Failed to re-subscribe after all retries")

    def process_data_queue(self):
        """Process data from queue and save to database"""
        batch_size = 100
        batch_data = []
        last_batch_time = time.time()
        batch_timeout = 5.0  # Process batch after 5 seconds even if not full

        while self.running:
            try:
                try:
                    data = self.data_queue.get(timeout=1)
                    batch_data.append(data)
                    self.data_queue.task_done()  # Mark task as done
                except queue.Empty:
                    current_time = time.time()
                    # Process batch if timeout exceeded or if we have data
                    if batch_data and (current_time - last_batch_time) > batch_timeout:
                        self.save_batch_to_db(batch_data)
                        batch_data = []
                        last_batch_time = current_time
                    continue

                # Process batch when it reaches the desired size
                if len(batch_data) >= batch_size:
                    self.save_batch_to_db(batch_data)
                    batch_data = []
                    last_batch_time = time.time()

            except Exception as e:
                logging.error(f"Error in data processing thread: {e}")
                self.stats['errors'] += 1

        # Process remaining data when shutting down
        if batch_data:
            self.save_batch_to_db(batch_data)

    def monitor_connection(self):
        """Monitor connection health and detect issues"""
        check_interval = 30  # Check every 30 seconds
        message_timeout = 60  # Expect at least one message per minute

        while self.running:
            try:
                time.sleep(check_interval)

                if not self.running:
                    break

                current_time = datetime.now()

                # Check if we haven't received messages for too long
                if (self.last_message_time and
                        (current_time - self.last_message_time).total_seconds() > message_timeout and
                        self.is_connected):
                    logging.warning(f"No messages received for {message_timeout} seconds - connection might be stale")

                    # Log current statistics
                    logging.info(f"Current stats - Connected: {self.is_connected}, "
                                 f"Messages: {self.stats['messages_received']}, "
                                 f"Queue size: {self.data_queue.qsize()}")

                # Log periodic status
                if self.stats['messages_received'] > 0:
                    messages_per_second = self.stats['messages_received'] / max(1, (current_time - self.stats['start_time']).total_seconds())
                    logging.info(f"Connection health - Messages/sec: {messages_per_second:.2f}, "
                                 f"Queue: {self.data_queue.qsize()}, "
                                 f"Reconnections: {self.stats['reconnections']}")

            except Exception as e:
                logging.error(f"Error in connection monitor: {e}")

    def save_batch_to_db(self, batch_data: List[Dict]):
        """Save batch of data to current database"""
        try:
            # Use current database path
            conn = sqlite3.connect(self.current_db_path, timeout=10.0)  # Add timeout
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
            self.subscribed_symbols = symbols.copy()  # Store symbols for reconnection
            self.data_type = data_type  # Store data type for reconnection

            session_id = f"session_v3_{int(time.time())}"
            self.create_session_record(session_id, symbols)

            # Start data processing thread
            processing_thread = threading.Thread(target=self.process_data_queue, daemon=True)
            processing_thread.start()
            logging.info("Data processing thread started")

            # Start connection monitoring thread
            monitor_thread = threading.Thread(target=self.monitor_connection, daemon=True)
            monitor_thread.start()
            logging.info("Connection monitoring thread started")

            # Initialize WebSocket with better reconnection settings
            self.websocket = data_ws.FyersDataSocket(
                access_token=self.access_token,
                log_path="",
                litemode=False,
                write_to_file=False,
                reconnect=True,  # Enable auto-reconnect
                reconnect_retry=5,  # Number of retry attempts (reduced for faster retries)
                on_connect=self.on_open,
                on_close=self.on_close,
                on_error=self.on_error,
                on_message=self.on_message
            )

            self._start_connection_thread()

            # Wait for initial connection with timeout
            connection_timeout = 30
            start_time = time.time()
            while not self.is_connected and (time.time() - start_time) < connection_timeout:
                time.sleep(0.1)

            if not self.is_connected:
                raise Exception("Failed to establish WebSocket connection within timeout")

            # Subscribe to symbols
            logging.info(f"Subscribing to {len(symbols)} symbols: {symbols}")
            self.websocket.subscribe(symbols=symbols, data_type=data_type)
            logging.info("Successfully subscribed to symbols")

            # Keep the WebSocket running
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
        """Create a session record in current database"""
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
            logging.info(f"Session record created: {session_id} in database: {os.path.basename(self.current_db_path)}")

        except Exception as e:
            logging.error(f"Error creating session record: {e}")

    def stop_streaming(self):
        """Stop the streaming process"""
        logging.info("Stopping streaming process...")
        self.running = False

        if self.websocket:
            try:
                self.websocket.close_connection()
            except Exception as e:
                logging.error(f"Error closing WebSocket: {e}")

        # Wait for data queue to be processed
        logging.info("Waiting for data queue to be processed...")
        try:
            self.data_queue.join()  # Wait for all queued items to be processed
        except Exception as e:
            logging.error(f"Error waiting for queue: {e}")

        duration = datetime.now() - self.stats['start_time'] if self.stats['start_time'] else timedelta(0)
        logging.info(f"Streaming stopped. Final Statistics:")
        logging.info(f"  Duration: {duration}")
        logging.info(f"  Messages received: {self.stats['messages_received']:,}")
        logging.info(f"  Messages saved: {self.stats['messages_saved']:,}")
        logging.info(f"  Errors: {self.stats['errors']:,}")
        logging.info(f"  Reconnections: {self.stats['reconnections']:,}")
        logging.info(f"  Current database: {self.current_db_path}")

    def get_historical_data(self, symbol: str, start_date: str, end_date: str, db_date: str = None) -> pd.DataFrame:
        """Retrieve historical data from database for specific date"""
        try:
            # Use specific database or current one
            if db_date:
                db_path = self.db_manager.get_daily_db_path(datetime.strptime(db_date, '%Y-%m-%d'))
                if not os.path.exists(db_path):
                    logging.warning(f"Database for date {db_date} not found: {db_path}")
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
        """Get summary of all available databases"""
        databases = self.db_manager.list_available_databases()
        summary_data = []

        for date_str, db_path in databases:
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()

                # Get record count
                cursor.execute("SELECT COUNT(*) FROM market_data")
                record_count = cursor.fetchone()[0]

                # Get unique symbols
                cursor.execute("SELECT COUNT(DISTINCT symbol) FROM market_data")
                symbol_count = cursor.fetchone()[0]

                # Get time range
                cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM market_data")
                time_range = cursor.fetchone()

                # Get file size
                file_size = os.path.getsize(db_path) / (1024 * 1024)  # MB

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


def setup_authentication():
    """Setup Fyers authentication with enhanced features"""
    print("\n" + "=" * 60)
    print("️  FYERS API AUTHENTICATION SETUP")
    print("=" * 60)

    # Check existing credentials
    if not os.environ.get('FYERS_CLIENT_ID'):
        print("\n Enter your Fyers API credentials:")
        client_id = input("Fyers Client ID: ").strip()
        secret_key = input("Fyers Secret Key: ").strip()

        if not client_id or not secret_key:
            print(" Both Client ID and Secret Key are required!")
            return False

        # Save to .env file
        auth_manager = FyersAuthManager()
        auth_manager.save_to_env('FYERS_CLIENT_ID', client_id)
        auth_manager.save_to_env('FYERS_SECRET_KEY', secret_key)

        # Reload environment
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
    """Test authentication and API connectivity"""
    print("\n" + "=" * 60)
    print(" TESTING FYERS API AUTHENTICATION")
    print("=" * 60)

    auth_manager = FyersAuthManager()
    token = auth_manager.get_valid_access_token()

    if token:
        print(" Authentication successful!")
        print(f" Access Token: {token[:20]}...")

        # Test API call
        try:
            print("\n Testing API connectivity...")
            headers = {'Authorization': f"{os.environ.get('FYERS_CLIENT_ID')}:{token}"}
            response = requests.get('https://api-t1.fyers.in/api/v3/profile', headers=headers)

            if response.status_code == 200:
                result = response.json()
                if result.get('s') == 'ok':
                    profile = result.get('data', {})
                    print(" API Connection successful!")
                    print(f" Name: {profile.get('name', 'Unknown')}")
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


def show_menu():
    """Display the main menu"""
    print("\n" + "=" * 60)
    print(" FYERS DATA STREAMING - DAILY DATABASE VERSION")
    print("=" * 60)
    print("1. Setup Authentication")
    print("2. Test Authentication")
    print("3. Start Data Streaming")
    print("4. View Streaming Stats")
    print("5. View Database Summary")
    print("6. Cleanup Old Databases")
    print("7. Update PIN")
    print("8. Exit")
    print("=" * 60)


def show_streaming_stats():
    """Show current streaming statistics"""
    db_manager = DatabaseManager()
    current_db_path = db_manager.get_current_db_path()

    if not os.path.exists(current_db_path):
        print(" No database found for today. Start streaming first.")
        return

    try:
        conn = sqlite3.connect(current_db_path)

        # Get session stats
        sessions_df = pd.read_sql_query('''
            SELECT session_id, start_time, symbols_count, messages_received, messages_saved, status, trading_date
            FROM streaming_sessions 
            ORDER BY start_time DESC 
            LIMIT 5
        ''', conn)

        # Get data stats
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
            print(" No market data found for today.")

    except Exception as e:
        print(f" Error reading stats: {e}")


def show_database_summary():
    """Show summary of all databases"""
    print("\n" + "=" * 60)
    print(" DATABASE SUMMARY")
    print("=" * 60)

    db_manager = DatabaseManager()

    try:
        # Initialize a temporary streamer to get database summary
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
            print(" No database files found.")

    except Exception as e:
        print(f" Error generating database summary: {e}")


def cleanup_old_databases():
    """Cleanup old databases interactively"""
    print("\n" + "=" * 60)
    print(" DATABASE CLEANUP")
    print("=" * 60)

    db_manager = DatabaseManager()

    try:
        # Show current databases
        databases = db_manager.list_available_databases()

        if not databases:
            print(" No database files found.")
            return

        print(f" Found {len(databases)} database files:")
        for i, (date_str, db_path) in enumerate(databases[:10], 1):  # Show first 10
            file_size = os.path.getsize(db_path) / (1024 * 1024)  # MB
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
            print(" Cleanup cancelled.")
            return
        else:
            print(" Invalid choice.")
            return

        # Confirm cleanup
        cutoff_date = datetime.now() - timedelta(days=keep_days)
        files_to_remove = [
            (date_str, db_path) for date_str, db_path in databases
            if datetime.strptime(date_str, '%Y-%m-%d') < cutoff_date
        ]

        if not files_to_remove:
            print(f" No files older than {keep_days} days found.")
            return

        print(f"\n Files to be removed ({len(files_to_remove)} files):")
        total_size = 0
        for date_str, db_path in files_to_remove:
            file_size = os.path.getsize(db_path) / (1024 * 1024)  # MB
            total_size += file_size
            print(f"   {date_str} - {os.path.basename(db_path)} ({file_size:.1f} MB)")

        print(f"\n Total space to be freed: {total_size:.1f} MB")

        confirm = input(f"\n Proceed with cleanup? (y/N): ").strip().lower()
        if confirm == 'y':
            removed_count = db_manager.cleanup_old_databases(keep_days)
            print(f"\n Cleanup completed: removed {removed_count} files")
        else:
            print(" Cleanup cancelled.")

    except Exception as e:
        print(f" Error during cleanup: {e}")


def update_pin():
    """Update the trading PIN"""
    print("\n" + "=" * 60)
    print(" UPDATE TRADING PIN")
    print("=" * 60)

    auth_manager = FyersAuthManager()

    # Clear existing PIN
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


def main():
    """Main function with enhanced authentication and daily database support"""

    # Handle command line arguments
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()

        if command == "auth":
            setup_authentication()
            return
        elif command == "test-auth":
            test_authentication()
            return
        elif command == "stream":
            # Direct streaming mode
            pass
        elif command == "cleanup":
            cleanup_old_databases()
            return
        else:
            print("Available commands:")
            print("  python main.py auth      - Setup authentication")
            print("  python main.py test-auth - Test authentication")
            print("  python main.py stream    - Start streaming directly")
            print("  python main.py cleanup   - Cleanup old databases")
            print("  python main.py           - Interactive menu")
            return

    # Interactive mode or direct streaming
    if len(sys.argv) == 1:
        # Show menu
        while True:
            show_menu()
            choice = input(" Select option (1-8): ").strip()

            if choice == "1":
                setup_authentication()
            elif choice == "2":
                test_authentication()
            elif choice == "3":
                break  # Continue to streaming
            elif choice == "4":
                show_streaming_stats()
            elif choice == "5":
                show_database_summary()
            elif choice == "6":
                cleanup_old_databases()
            elif choice == "7":
                update_pin()
            elif choice == "8":
                print(" Goodbye!")
                return
            else:
                print(" Invalid choice. Please select 1-8.")

    # Main streaming logic
    try:
        print("\n" + "=" * 60)
        print(" STARTING FYERS DATA STREAMING - DAILY DATABASE MODE")
        print("=" * 60)

        # Enhanced authentication
        auth_manager = FyersAuthManager()
        access_token = auth_manager.get_valid_access_token()

        if not access_token:
            print(" Authentication failed!")
            print(" Please run authentication setup first.")
            print(" Command: python main.py auth")
            return

        CLIENT_ID = os.environ.get('FYERS_CLIENT_ID')

        # Initialize database manager
        db_manager = DatabaseManager()
        current_db_path = db_manager.get_current_db_path()

        # Symbols to stream - you can customize this list
        SYMBOLS = [
            # "NSE:STLNETWORK-EQ",
            # "NSE:STLTECH-EQ",
            # "NSE:SKYGOLD-EQ",
            "NSE:SBILIFE25OCT1860CE",
            "NSE:SBILIFE25OCT1860PE",
            "NSE:KOTAKBANK25OCT2200CE",
            "NSE:KOTAKBANK25OCT2200PE",
            "NSE:DRREDDY25OCT1260CE",
            "NSE:DRREDDY25OCT1260PE",
            "NSE:NTPC25OCT345CE",
            "NSE:NTPC25OCT345PE",
            "NSE:COFORGE25OCT1700CE",
            "NSE:COFORGE25OCT1700PE",
            "NSE:NIFTY25OCT25850CE",  # NIFTY CALL
            "NSE:NIFTY25OCT25850PE",  # NIFTY PUT
            "NSE:BANKNIFTY25OCT58000CE",  # BANK-NIFTY CALL
            "NSE:BANKNIFTY25OCT58000PE",  # BANK-NIFTY PUT
            "NSE:FINNIFTY25OCT27500CE",  # FIN-NIFTY CALL
            "NSE:FINNIFTY25OCT27500PE",  # FIN-NIFTY PUT
            "NSE:MIDCPNIFTY25OCT13250CE",  # MIDCAP-NIFTY CALL
            "NSE:MIDCPNIFTY25OCT13250PE"  # MIDCAP-NIFTY PUT
        ]

        print(f" Authentication successful!")
        print(f" Client ID: {CLIENT_ID}")
        print(f" Symbols to stream: {len(SYMBOLS)}")
        print(f" Current Database: {current_db_path}")
        print(f" Trading Date: {datetime.now().strftime('%Y-%m-%d')}")
        print(f" Data Type: DepthUpdate (Real-time quotes)")
        print(f" Database Directory: {db_manager.db_directory}")

        # Show existing databases
        existing_dbs = db_manager.list_available_databases()
        if existing_dbs:
            print(f" Found {len(existing_dbs)} existing database files")
            print(f" Latest: {existing_dbs[0][0]} - {os.path.basename(existing_dbs[0][1])}")

        # Initialize and run streamer
        streamer = FyersDataStreamerV3(CLIENT_ID, access_token, db_manager)

        print(f"\nInitializing WebSocket connection...")
        print(f"Note: Database will automatically switch to new file at midnight")
        streamer.start_streaming(SYMBOLS, data_type="SymbolUpdate") #SymbolUpdate,DepthUpdate

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