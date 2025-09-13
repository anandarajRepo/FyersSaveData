import sqlite3
import json
import logging
import threading
import time
from datetime import datetime, timedelta
import queue
from fyers_apiv3 import fyersModel
from fyers_apiv3.FyersWebsocket import data_ws
import pandas as pd
import os
from typing import Dict, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('fyers_streaming.log'),
        logging.StreamHandler()
    ]
)


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
            print(message)

            # Fyers API v3 message format
            if message:
                # Add processing timestamp
                message['processing_timestamp'] = datetime.now().isoformat()

                # Add to queue for processing
                self.data_queue.put(message)

                if self.stats['messages_received'] % 1000 == 0:
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
                # Get data from queue with timeout
                try:
                    data = self.data_queue.get(timeout=1)
                    batch_data.append(data)
                except queue.Empty:
                    # Process any remaining data in batch
                    if batch_data:
                        self.save_batch_to_db(batch_data)
                        batch_data = []
                    continue

                # Process batch when it reaches batch_size
                if len(batch_data) >= batch_size:
                    self.save_batch_to_db(batch_data)
                    batch_data = []

            except Exception as e:
                logging.error(f"Error in data processing thread: {e}")
                self.stats['errors'] += 1

        # Process any remaining data
        if batch_data:
            self.save_batch_to_db(batch_data)

    def save_batch_to_db(self, batch_data: List[Dict]):
        """Save batch of data to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            for data in batch_data:
                try:
                    # Determine data type and save accordingly
                    if 'symbol' in data and 'ltp' in data:
                        self.save_market_data(cursor, data)
                    elif 'bids' in data and 'asks' in data:
                        self.save_depth_data(cursor, data)
                    else:
                        # Save as generic market data
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

        # Extract bid and ask data
        bids = data.get('bids', [])
        asks = data.get('asks', [])

        # Pad with None if less than 5 levels
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

    def get_symbols_info(self, symbols: List[str]) -> Dict:
        """Get symbol information using Fyers API v3"""
        try:
            # Get symbol master data
            symbol_info = {}
            for symbol in symbols:
                try:
                    # Extract exchange and symbol
                    parts = symbol.split(':')
                    if len(parts) == 2:
                        exchange = parts[0]
                        symbol_name = parts[1]

                        # You can enhance this with actual API calls to get token info
                        symbol_info[symbol] = {
                            'symbol': symbol,
                            'exchange': exchange,
                            'symbol_name': symbol_name,
                            'token': hash(symbol) % 1000000  # Placeholder - use actual token from API
                        }

                except Exception as e:
                    logging.error(f"Error getting info for symbol {symbol}: {e}")

            return symbol_info

        except Exception as e:
            logging.error(f"Error getting symbols info: {e}")
            return {}

    def start_streaming(self, symbols: List[str], data_type: str = "SymbolUpdate"):
        """
        Start streaming data for given symbols using Fyers API v3

        Args:
            symbols: List of symbols to stream (e.g., ['NSE:SBIN-EQ', 'NSE:RELIANCE-EQ'])
            data_type: Type of data to stream (SymbolUpdate, MarketDepth, etc.)
        """
        try:
            self.running = True
            self.stats['start_time'] = datetime.now()

            # Get symbol information
            self.symbol_mapping = self.get_symbols_info(symbols)

            # Create session record
            session_id = f"session_v3_{int(time.time())}"
            self.create_session_record(session_id, symbols)

            # Start data processing thread
            processing_thread = threading.Thread(target=self.process_data_queue, daemon=True)
            processing_thread.start()
            logging.info("Data processing thread started")

            # Initialize WebSocket connection for API v3
            self.websocket = data_ws.FyersDataSocket(
                access_token=self.access_token,
                log_path="",
                litemode=False,
                write_to_file=False,
                reconnect=True,  # Enable auto-reconnection to WebSocket on disconnection.
                reconnect_retry=10,  # Number of times re-connection will be attempted in case
                on_connect=self.on_open,
                on_close=self.on_close,
                on_error=self.on_error,
                on_message=self.on_message
            )

            # Start connection in background thread
            self._start_connection_thread()

            # Wait for connection
            while not self.is_connected:
                time.sleep(0.1)

            # Subscribe to symbols
            self.websocket.subscribe(symbols=symbols, data_type=data_type)
            logging.info(f"Subscribed to {len(symbols)} symbols: {symbols}")

            # Start the connection
            self.websocket.keep_running()

            if self.is_connected:
                logging.info("Fyers WebSocket connected successfully")
                return True
            else:
                logging.error("Fyers WebSocket connection timeout")
                return False

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

        # Print final statistics
        duration = datetime.now() - self.stats['start_time'] if self.stats['start_time'] else timedelta(0)
        logging.info(f"Streaming stopped. Statistics:")
        logging.info(f"  Duration: {duration}")
        logging.info(f"  Messages received: {self.stats['messages_received']}")
        logging.info(f"  Messages saved: {self.stats['messages_saved']}")
        logging.info(f"  Errors: {self.stats['errors']}")
        logging.info(f"  Connection status: {self.stats['connection_status']}")

    def get_historical_data(self, symbol: str, start_date: str, end_date: str, include_depth: bool = False) -> pd.DataFrame:
        """
        Retrieve historical data from database

        Args:
            symbol: Symbol to query
            start_date: Start date (YYYY-MM-DD HH:MM:SS)
            end_date: End date (YYYY-MM-DD HH:MM:SS)
            include_depth: Whether to include market depth data

        Returns:
            DataFrame with historical data
        """
        try:
            conn = sqlite3.connect(self.db_path)

            if include_depth:
                # Join market data with depth data
                df = pd.read_sql_query('''
                    SELECT m.timestamp, m.symbol, m.ltp, m.open_price, m.high_price, m.low_price, 
                           m.close_price, m.volume, m.bid_price, m.ask_price, m.price_change, m.price_change_percent,
                           d.bid_1_price, d.bid_1_qty, d.ask_1_price, d.ask_1_qty
                    FROM market_data m
                    LEFT JOIN market_depth d ON m.symbol = d.symbol AND m.timestamp = d.timestamp
                    WHERE m.symbol = ? AND m.timestamp BETWEEN ? AND ?
                    ORDER BY m.timestamp
                ''', conn, params=(symbol, start_date, end_date))
            else:
                df = pd.read_sql_query('''
                    SELECT timestamp, symbol, ltp, open_price, high_price, low_price, close_price,
                           volume, bid_price, ask_price, price_change, price_change_percent, oi, oi_change
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

    def get_stats(self) -> Dict:
        """Get current streaming statistics"""
        stats = self.stats.copy()
        if stats['start_time']:
            stats['duration_minutes'] = (datetime.now() - stats['start_time']).total_seconds() / 60
            if stats['duration_minutes'] > 0:
                stats['messages_per_minute'] = stats['messages_received'] / stats['duration_minutes']
        return stats


def main():
    """Main function to run the streaming application with Fyers API v3"""

    # Configuration - Replace with your actual credentials
    CLIENT_ID = "X23KTOMB05-100"  # Replace with your Fyers client ID
    ACCESS_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiZDoxIiwiZDoyIiwieDowIiwieDoxIiwieDoyIl0sImF0X2hhc2giOiJnQUFBQUFCb3c2V1otWHZQdGRDQU9mMkdPYzMxUVlCZFhmSE9CN055QW5JR0NLdERuU2JWeExUY3dGd181X2l2ZUlheHNRZXZHa3FGZ09MakZ5Vk9ibzJnTVNZLXRxNWw3MFJFV2ZocGctVnVWb1lxc2sySzZfWT0iLCJkaXNwbGF5X25hbWUiOiIiLCJvbXMiOiJLMSIsImhzbV9rZXkiOiI3MzhmOGJiZDdhNmE3MDQ5ZDgxZWQzMTEwM2M4MTg5OTQ0NjAzNDFlOWNhYzdmOGE3ZWNhMTk2NiIsImlzRGRwaUVuYWJsZWQiOiJOIiwiaXNNdGZFbmFibGVkIjoiTiIsImZ5X2lkIjoiREcwMDAxMyIsImFwcFR5cGUiOjEwMCwiZXhwIjoxNzU3NzIzNDAwLCJpYXQiOjE3NTc2NTIzNzcsImlzcyI6ImFwaS5meWVycy5pbiIsIm5iZiI6MTc1NzY1MjM3Nywic3ViIjoiYWNjZXNzX3Rva2VuIn0.q48U9Neue78iVz6nSywMQfcFJQcDM3MYFruiZ4F1MCs"  # Replace with your Fyers API v3 access token

    # Symbols to stream (adjust as needed)
    SYMBOLS = [
        "NSE:SBIN-EQ",  # State Bank of India
        "NSE:RELIANCE-EQ",  # Reliance Industries
        "NSE:TCS-EQ",  # Tata Consultancy Services
        "NSE:INFY-EQ",  # Infosys
        "NSE:HDFCBANK-EQ"  # HDFC Bank
    ]

    # Database path
    DB_PATH = "fyers_market_data_v3.db"

    try:
        # Initialize streamer with API v3
        streamer = FyersDataStreamerV3(CLIENT_ID, ACCESS_TOKEN, DB_PATH)

        logging.info("Starting Fyers API v3 data streaming...")
        logging.info(f"Symbols: {SYMBOLS}")
        logging.info(f"Database: {DB_PATH}")

        # Start streaming with SymbolUpdate for real-time quotes
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
    main()