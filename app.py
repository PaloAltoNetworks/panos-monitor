import flask, io, csv
from flask import Response, send_file
import sqlite3
import os
import time
import requests, shutil, re
from datetime import datetime
import xml.etree.ElementTree as ET
from urllib3.exceptions import InsecureRequestWarning
import multiprocessing
import threading
from cryptography.fernet import Fernet
import uuid
import report_generator
import logging

# --- Configuration ---
DB_FILE = "monitoring.db"
KEY_FILE = "secret.key"

# Suppress insecure request warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# --- NEW: Import FPDF for the custom PDF class ---
from fpdf import FPDF

# --- NEW: Custom PDF class for branded header and footer ---
class PDF(FPDF):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.PANW_RED = (255, 69, 0)
        self.PANW_GRAY = (70, 70, 70)
        # Correctly join path relative to the app's location
        self.LOGO_PATH = os.path.join(os.path.dirname(__file__), 'static', 'panw-logo.png')
        self._draw_header_footer = True

    def set_draw_header_footer(self, draw):
        self._draw_header_footer = draw

    def header(self):
        if not self._draw_header_footer: return
        if os.path.exists(self.LOGO_PATH):
            self.image(self.LOGO_PATH, 10, 8, 33)
        self.set_font('Helvetica', 'B', 20)
        self.set_text_color(*self.PANW_RED)
        self.cell(0, 10, 'PAN-OS Performance & Capacity Report', 0, 1, 'C')
        self.ln(5)
        # Draw a line under the header
        self.set_draw_color(*self.PANW_RED)
        self.line(10, 30, self.w - 10, 30)
        self.ln(10)

    def footer(self):
        if not self._draw_header_footer: return
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        # Add a watermark logo
        if os.path.exists(self.LOGO_PATH):
            self.image(self.LOGO_PATH, x=self.w - 40, y=self.h - 12, w=8, link='', type='PNG')
        self.set_text_color(128)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

# --- Encryption Functions ---
def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file: key_file.write(key)
    return key

def load_key():
    if not os.path.exists(KEY_FILE): return generate_key()
    return open(KEY_FILE, "rb").read()

def encrypt_message(message, key):
    return Fernet(key).encrypt(message.encode())

def decrypt_message(encrypted_message, key):
    return Fernet(key).decrypt(encrypted_message).decode()

# --- Flask App Setup ---
app = flask.Flask(__name__)
app.secret_key = os.urandom(24) 

# --- NEW: Global lock for thread-safe database writes ---
db_lock = threading.Lock()
background_task_running = threading.Event()
background_task_message = ""
message_lock = threading.Lock()
manual_poll_event = threading.Event()

# --- NEW: Context processor to inject background task status into all templates ---
@app.context_processor
def inject_background_task_status():
    with message_lock:
        message = background_task_message if background_task_running.is_set() else ""
    return dict(background_task_is_running=background_task_running.is_set(), background_task_message=message)

@app.context_processor
def inject_theme():
    conn = get_db_connection()
    theme_setting = conn.execute("SELECT value FROM settings WHERE key = 'THEME'").fetchone()
    conn.close()
    return dict(current_theme=theme_setting['value'] if theme_setting else 'light')

# --- Database Functions ---
def get_db_connection():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('PRAGMA foreign_keys = ON;')
    conn.execute('''CREATE TABLE IF NOT EXISTS firewalls (id INTEGER PRIMARY KEY AUTOINCREMENT, ip_address TEXT UNIQUE NOT NULL, last_checked TIMESTAMP, status TEXT DEFAULT 'unknown', last_poll_status TEXT);''')
    conn.execute('''CREATE TABLE IF NOT EXISTS stats (id INTEGER PRIMARY KEY AUTOINCREMENT, firewall_id INTEGER NOT NULL, timestamp TIMESTAMP NOT NULL, active_sessions INTEGER, ssl_decrypt_sessions INTEGER, total_input_bps REAL, total_output_bps REAL, cpu_load REAL, dataplane_load REAL, FOREIGN KEY (firewall_id) REFERENCES firewalls (id) ON DELETE CASCADE);''')
    # ** NEW: Table for firewall model specifications **
    conn.execute('''CREATE TABLE IF NOT EXISTS firewall_models (model TEXT PRIMARY KEY, generation TEXT, max_sessions INTEGER, max_throughput_mbps INTEGER, max_ssl_decrypt_sessions INTEGER);''')
    conn.execute('''CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);''')
    conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('THEME', 'light')")
    conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('ALERT_THRESHOLD', '80')")
    conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('POLL_INTERVAL', '30')")
    conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('DATA_RETENTION_DAYS', '90')")
    
    # ** NEW: Add 'model' column to the firewalls table if it doesn't exist **
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(firewalls)")
    columns = [row['name'] for row in cursor.fetchall()]
    if 'model' not in columns:
        conn.execute("ALTER TABLE firewalls ADD COLUMN model TEXT;")
    if 'hostname' not in columns:
        conn.execute("ALTER TABLE firewalls ADD COLUMN hostname TEXT;")
    if 'sw_version' not in columns:
        conn.execute("ALTER TABLE firewalls ADD COLUMN sw_version TEXT;")
    if 'last_poll_status' not in columns:
        conn.execute("ALTER TABLE firewalls ADD COLUMN last_poll_status TEXT;")

    # ** NEW: Table for detailed firewall specifications/capacities **
    conn.execute('''
        CREATE TABLE IF NOT EXISTS firewall_details (
            firewall_id INTEGER PRIMARY KEY,
            max_sessions INTEGER,
            max_rules INTEGER,
            max_nat_rules INTEGER, 
            max_ssl_decrypt_rules INTEGER,
            max_qos_rules INTEGER,
            max_pbf_rules INTEGER,
            max_dos_rules INTEGER,
            max_zones INTEGER,
            max_vsys INTEGER,
            max_virtual_routers INTEGER,
            max_vlans INTEGER,
            max_ike_peers INTEGER,
            max_ipsec_tunnels INTEGER,
            max_ssl_tunnels INTEGER, 
            advance_routing_enabled BOOLEAN,
            max_addr_per_group INTEGER,
            max_cert_cache INTEGER,
            max_dns_cache INTEGER,
            max_ipv6_addrs INTEGER,
            max_mac_addrs INTEGER,
            max_security_profiles INTEGER,
            max_url_patterns INTEGER, 
            max_vwires INTEGER,
            max_hip_objects INTEGER,
            max_custom_signatures INTEGER,
            max_interfaces INTEGER,
            max_bfd_sessions INTEGER,
            max_sdwan_rules INTEGER,
            max_mroutes INTEGER, 
            max_schedules INTEGER,
            max_edl_objects INTEGER,
            max_registered_ips INTEGER,
            max_ts_agents INTEGER,
            max_proxy_sessions INTEGER,
            max_auth_rules INTEGER, 
            max_address_objects INTEGER,
            max_address_groups INTEGER,
            max_service_objects INTEGER,
            max_service_groups INTEGER,
            max_routes INTEGER,
            max_arp_entries INTEGER,
            FOREIGN KEY (firewall_id) REFERENCES firewalls (id) ON DELETE CASCADE);
    ''')

    # ** NEW: Table for current firewall object usage/counts **
    conn.execute('''
        CREATE TABLE IF NOT EXISTS firewall_current_usage (
            firewall_id INTEGER PRIMARY KEY,
            last_updated TIMESTAMP,
            current_rules INTEGER,
            current_nat_rules INTEGER,
            current_address_objects INTEGER,
            current_service_objects INTEGER,
            current_ipsec_tunnels INTEGER,
            current_routes INTEGER,
            current_mroutes INTEGER,
            current_arp_entries INTEGER,
            current_bfd_sessions INTEGER,
            current_dns_cache INTEGER,
            current_ssl_decrypt_sessions INTEGER,
            current_registered_ips INTEGER,
            FOREIGN KEY (firewall_id) REFERENCES firewalls (id) ON DELETE CASCADE
        );
    ''')

    # ** NEW: Table for storing capacity alerts **
    conn.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            firewall_id INTEGER NOT NULL,
            metric_name TEXT NOT NULL,
            utilization REAL NOT NULL,
            timestamp TIMESTAMP NOT NULL,
            acknowledged BOOLEAN DEFAULT 0,
            FOREIGN KEY (firewall_id) REFERENCES firewalls (id) ON DELETE CASCADE
        );
    ''')

    # ** NEW: Table for storing PDF generation jobs **
    conn.execute('''
        CREATE TABLE IF NOT EXISTS pdf_jobs (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            timestamp TIMESTAMP NOT NULL,
            status TEXT DEFAULT 'pending'
        );
    ''')


    # ** FIX: Add missing columns to firewall_current_usage table for existing databases **
    cursor.execute("PRAGMA table_info(firewall_current_usage)")
    usage_columns = {row['name'] for row in cursor.fetchall()}
    required_usage_columns = {
        'current_routes': 'INTEGER',
        'current_mroutes': 'INTEGER',
        'current_arp_entries': 'INTEGER',
        'current_bfd_sessions': 'INTEGER',
        'current_dns_cache': 'INTEGER',
        'current_registered_ips': 'INTEGER',
        'current_ssl_decrypt_sessions': 'INTEGER'
    }
    for col, col_type in required_usage_columns.items():
        if col not in usage_columns:
            print(f"Database schema outdated. Adding column '{col}' to 'firewall_current_usage' table...")
            conn.execute(f"ALTER TABLE firewall_current_usage ADD COLUMN {col} {col_type};")

    # ** FIX: Add missing columns to firewall_details table for existing databases **
    cursor.execute("PRAGMA table_info(firewall_details)")
    details_columns = {row['name'] for row in cursor.fetchall()}
    required_details_columns = {
        'advance_routing_enabled': 'BOOLEAN',
    }
    for col, col_type in required_details_columns.items():
        if col not in details_columns:
            print(f"Database schema outdated. Adding column '{col}' to 'firewall_details' table...")
            conn.execute(f"ALTER TABLE firewall_details ADD COLUMN {col} {col_type};")

    # ** FIX: Add missing columns to stats and firewall_models tables **
    cursor.execute("PRAGMA table_info(stats)")
    stats_columns = {row['name'] for row in cursor.fetchall()}
    if 'ssl_decrypt_sessions' not in stats_columns:
        print("Database schema outdated. Adding column 'ssl_decrypt_sessions' to 'stats' table...")
        conn.execute("ALTER TABLE stats ADD COLUMN ssl_decrypt_sessions INTEGER;")

    cursor.execute("PRAGMA table_info(firewall_models)")
    model_columns = {row['name'] for row in cursor.fetchall()}
    if 'max_ssl_decrypt_sessions' not in model_columns:
        print("Database schema outdated. Adding column 'max_ssl_decrypt_sessions' to 'firewall_models' table...")
        conn.execute("ALTER TABLE firewall_models ADD COLUMN max_ssl_decrypt_sessions INTEGER;")
    if 'memory_utilization' not in stats_columns:
        print("Database schema outdated. Adding column 'memory_utilization' to 'stats' table...")
        conn.execute("ALTER TABLE stats ADD COLUMN memory_utilization REAL;")

    # ** NEW: One-time data seeding from pa_models.py to the database **
    seed_firewall_models(conn)

    # ** NEW: Seed the database with a default list of firewalls if it's empty **
    seed_initial_firewalls(conn)

    conn.commit()
    conn.close()

def seed_firewall_models(conn):
    """One-time migration of firewall specs from pa_models.py into the database."""
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM firewall_models")
    if cursor.fetchone()[0] > 0:
        return # Table is already populated

    # This list is now self-contained and no longer depends on pa_models.py
    DEFAULT_MODELS = [
    {'model': 'PA-220', 'max_sessions': 64000, 'max_throughput_mbps': 320, 'generation': '3'},
    {'model': 'PA-820', 'max_sessions': 128000, 'max_throughput_mbps': 800, 'generation': '3'},
    {'model': 'PA-850', 'max_sessions': 192000, 'max_throughput_mbps': 900, 'generation': '3'},
    {'model': 'PA-3220', 'max_sessions': 1000000, 'max_throughput_mbps': 2200, 'generation': '3'},
    {'model': 'PA-3250', 'max_sessions': 2000000, 'max_throughput_mbps': 2500, 'generation': '3'},
    {'model': 'PA-3260', 'max_sessions': 2200000, 'max_throughput_mbps': 4000, 'generation': '3'},
    {'model': 'PA-5220', 'max_sessions': 4000000, 'max_throughput_mbps': 8800, 'generation': '3'},
    {'model': 'PA-5250', 'max_sessions': 8000000, 'max_throughput_mbps': 19000, 'generation': '3'},
    {'model': 'PA-5260', 'max_sessions': 32000000, 'max_throughput_mbps': 31000, 'generation': '3'},
    {'model': 'PA-5280', 'max_sessions': 64000000, 'max_throughput_mbps': 31000, 'generation': '3'},
    {'model': 'PA-7050', 'max_sessions': 245000000, 'max_throughput_mbps': 184000, 'generation': '3'},
    {'model': 'PA-7080', 'max_sessions': 416000000, 'max_throughput_mbps': 305000, 'generation': '3'},
    {'model': 'PA-410', 'max_sessions': 64000, 'max_throughput_mbps': 780, 'generation': '4'},
    {'model': 'PA-410R', 'max_sessions': 64000, 'max_throughput_mbps': 780, 'generation': '4'},
    {'model': 'PA-410R-5G', 'max_sessions': 64000, 'max_throughput_mbps': 780, 'generation': '4'},
    {'model': 'PA-415', 'max_sessions': 64000, 'max_throughput_mbps': 800, 'generation': '4'},
    {'model': 'PA-415-5G', 'max_sessions': 64000, 'max_throughput_mbps': 800, 'generation': '4'},
    {'model': 'PA-440', 'max_sessions': 200000, 'max_throughput_mbps': 1200, 'generation': '4'},
    {'model': 'PA-445', 'max_sessions': 200000, 'max_throughput_mbps': 1225, 'generation': '4'},
    {'model': 'PA-450', 'max_sessions': 200000, 'max_throughput_mbps': 1900, 'generation': '4'},
    {'model': 'PA-450R', 'max_sessions': 200000, 'max_throughput_mbps': 1900, 'generation': '4'},
    {'model': 'PA-450R-5G', 'max_sessions': 200000, 'max_throughput_mbps': 1900, 'generation': '4'},
    {'model': 'PA-455', 'max_sessions': 300000, 'max_throughput_mbps': 2300, 'generation': '4'},
    {'model': 'PA-460', 'max_sessions': 400000, 'max_throughput_mbps': 3000, 'generation': '4'},
    {'model': 'PA-1410', 'max_sessions': 945000, 'max_throughput_mbps': 4500, 'generation': '4'},
    {'model': 'PA-1420', 'max_sessions': 1400000, 'max_throughput_mbps': 6200, 'generation': '4'},
    {'model': 'PA-3410', 'max_sessions': 1400000, 'max_throughput_mbps': 7500, 'generation': '4'},
    {'model': 'PA-3420', 'max_sessions': 2200000, 'max_throughput_mbps': 10000, 'generation': '4'},
    {'model': 'PA-3430', 'max_sessions': 2500000, 'max_throughput_mbps': 15000, 'generation': '4'},
    {'model': 'PA-3440', 'max_sessions': 3000000, 'max_throughput_mbps': 20000, 'generation': '4'},
    {'model': 'PA-5410', 'max_sessions': 5000000, 'max_throughput_mbps': 35000, 'generation': '4'},
    {'model': 'PA-5420', 'max_sessions': 7000000, 'max_throughput_mbps': 50000, 'generation': '4'},
    {'model': 'PA-5430', 'max_sessions': 9000000, 'max_throughput_mbps': 60000, 'generation': '4'},
    {'model': 'PA-5440', 'max_sessions': 20000000, 'max_throughput_mbps': 70000, 'generation': '4'},
    {'model': 'PA-5445', 'max_sessions': 48000000, 'max_throughput_mbps': 76000, 'generation': '4'},
    {'model': 'PA-5450', 'max_sessions': 100000000, 'max_throughput_mbps': 189000, 'generation': '4'},
    {'model': 'PA-505', 'max_sessions': 64000, 'max_throughput_mbps': 800, 'generation': '5'},
    {'model': 'PA-510', 'max_sessions': 100000, 'max_throughput_mbps': 1200, 'generation': '5'},
    {'model': 'PA-520', 'max_sessions': 150000, 'max_throughput_mbps': 1800, 'generation': '5'},
    {'model': 'PA-540', 'max_sessions': 250000, 'max_throughput_mbps': 2300, 'generation': '5'},
    {'model': 'PA-545-POE', 'max_sessions': 300000, 'max_throughput_mbps': 3000, 'generation': '5'},
    {'model': 'PA-550', 'max_sessions': 450000, 'max_throughput_mbps': 4000, 'generation': '5'},
    {'model': 'PA-555-POE', 'max_sessions': 450000, 'max_throughput_mbps': 5000, 'generation': '5'},
    {'model': 'PA-560', 'max_sessions': 600000, 'max_throughput_mbps': 6000, 'generation': '5'},
    {'model': 'PA-5540', 'max_sessions': 39000000, 'max_throughput_mbps': 90000, 'generation': '5'},
    {'model': 'PA-5550', 'max_sessions': 49000000, 'max_throughput_mbps': 120000, 'generation': '5'},
    {'model': 'PA-5560', 'max_sessions': 74000000, 'max_throughput_mbps': 180000, 'generation': '5'},
    {'model': 'PA-5570', 'max_sessions': 89000000, 'max_throughput_mbps': 240000, 'generation': '5'},
    {'model': 'PA-5580', 'max_sessions': 99000000, 'max_throughput_mbps': 300000, 'generation': '5'},
    {'model': 'PA-7500', 'max_sessions': 440000000, 'max_throughput_mbps': 1440000, 'generation': '5'},
    ]

    print("Database is new. Seeding firewall_models table with default data...")
    for spec in DEFAULT_MODELS:
        conn.execute(
            "INSERT OR IGNORE INTO firewall_models (model, generation, max_sessions, max_throughput_mbps) VALUES (?, ?, ?, ?)",
            (spec['model'], spec.get('generation', 'N/A'), spec['max_sessions'], spec['max_throughput_mbps'])
        )
    print("Seeding complete.")

def seed_initial_firewalls(conn):
    """If the firewalls table is empty, seed it with a default list of devices."""
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM firewalls")
    if cursor.fetchone()[0] > 0:
        return # Table is already populated

    # --- EDIT THIS LIST TO PRE-POPULATE YOUR DATABASE ---
    DEFAULT_FIREWALLS = [
        # '192.168.1.1',
        # '10.0.0.1'
    ]

    if not DEFAULT_FIREWALLS: return

    print(f"Database is new. Seeding with {len(DEFAULT_FIREWALLS)} default firewalls...")
    for ip in DEFAULT_FIREWALLS:
        conn.execute('INSERT OR IGNORE INTO firewalls (ip_address) VALUES (?)', (ip,))

def load_specs_from_db(conn):
    """Loads all model specifications from the database into a dictionary."""
    models = conn.execute("SELECT * FROM firewall_models").fetchall()
    return {m['model']: dict(m) for m in models}

# --- Web Page Routes ---
@app.route('/')
def index():
    conn = get_db_connection()
    specs_map = load_specs_from_db(conn)
    
    settings_row = conn.execute("SELECT value FROM settings WHERE key = 'POLL_INTERVAL'").fetchone()
    polling_interval = int(settings_row['value']) if settings_row else 30

    query = """
        SELECT f.id as firewall_id, f.ip_address, f.hostname, f.model, s.timestamp,
               COALESCE(s.active_sessions, 0) as active_sessions, 
               (COALESCE(s.total_input_bps, 0) / 1000000) as total_input_mbps, 
               (COALESCE(s.total_output_bps, 0) / 1000000) as total_output_mbps,
               COALESCE(s.cpu_load, 0) as cpu_load,
               COALESCE(s.dataplane_load, 0) as dataplane_load, 
               COALESCE(s.memory_utilization, 0) as memory_utilization,
               f.status
        FROM firewalls f
        LEFT JOIN (
            SELECT firewall_id, MAX(timestamp) as max_ts FROM stats GROUP BY firewall_id
        ) as latest_s ON f.id = latest_s.firewall_id
        LEFT JOIN stats s ON s.firewall_id = latest_s.firewall_id AND s.timestamp = latest_s.max_ts
        ORDER BY f.ip_address;
    """
    stats_from_db = conn.execute(query).fetchall()
    conn.close()
    
    # Process the results to add generation and format the timestamp
    processed_stats = []
    for stat in stats_from_db:
        # Convert the database row to a mutable dictionary
        stat_dict = dict(stat)
        
        # Look up the generation based on the model
        # This part remains the same, as the data structure is compatible
        model = stat_dict.get('model')
        stat_dict['generation'] = specs_map.get(model, {}).get('generation', 'N/A')
        
        # Reformat the timestamp string to remove fractional seconds
        if stat_dict['timestamp']:
            try:
                dt_obj = datetime.strptime(stat_dict['timestamp'], '%Y-%m-%d %H:%M:%S.%f')
                stat_dict['timestamp'] = dt_obj.strftime('%Y-%m-%d %H:%M:%S')
            except ValueError:
                # If parsing fails for any reason, just pass it through
                pass
        
        processed_stats.append(stat_dict)

    return flask.render_template('index.html', stats=processed_stats, polling_interval=polling_interval)

@app.route('/advisor', methods=['GET', 'POST'])
def advisor():
    results = None
    # ** FIX: Fetch threshold on both GET and POST **
    conn = get_db_connection()
    settings = {row['key']: row['value'] for row in conn.execute("SELECT key, value FROM settings").fetchall()}
    alert_threshold = int(settings.get('ALERT_THRESHOLD', 80))
    conn.close()

    selected_timespan = '7d' # Default value
    if flask.request.method == 'POST':
        selected_timespan = flask.request.form['timespan']
        time_modifier = {'7d': '-7 days', '30d': '-30 days'}.get(selected_timespan, '-7 days')

        conn = get_db_connection()
        specs_map = load_specs_from_db(conn)
        specs_list = conn.execute("SELECT * FROM firewall_models").fetchall()
        firewalls = conn.execute('SELECT id, ip_address, hostname, model FROM firewalls').fetchall()
        
        results = []
        for fw in firewalls:
            res = {'ip_address': fw['ip_address'], 'model': fw['model'], 'hostname': fw['hostname']}
            
            query = f"SELECT MAX(active_sessions) as max_s, MAX(total_input_bps) as max_in, MAX(total_output_bps) as max_out FROM stats WHERE firewall_id = ? AND timestamp >= datetime('now', 'localtime', '{time_modifier}');"
            peak_stats = conn.execute(query, (fw['id'],)).fetchone()

            peak_sessions = peak_stats['max_s'] or 0
            # ** NEW: Use the greater of peak input or peak output for the analysis **
            peak_throughput_mbps = max(peak_stats['max_in'] or 0, peak_stats['max_out'] or 0) / 1000000
            
            res['peak_sessions'] = peak_sessions
            res['peak_throughput'] = peak_throughput_mbps

            if fw['model'] and fw['model'] in specs_map:
                spec = specs_map[fw['model']]
                # ** NEW: Add generation to the results dictionary **
                res['generation'] = spec.get('generation', 'N/A')
                res['max_sessions'] = spec['max_sessions']
                res['max_throughput'] = spec['max_throughput_mbps']
                
                res['session_util'] = (peak_sessions / spec['max_sessions']) * 100 if spec['max_sessions'] > 0 else 0
                res['throughput_util'] = (peak_throughput_mbps / spec['max_throughput_mbps']) * 100 if spec['max_throughput_mbps'] > 0 else 0

                recommendations = []
                if res['session_util'] >= alert_threshold or res['throughput_util'] >= alert_threshold:
                    # --- Same-gen upgrade logic ---
                    current_generation = spec.get('generation', 'N/A')
                    same_gen_models = sorted([s for s in specs_list if s['generation'] == current_generation], key=lambda x: x['max_throughput_mbps'])
                    current_index = next((i for i, item in enumerate(same_gen_models) if item["model"] == fw['model']), -1)

                    if 0 <= current_index < len(same_gen_models) - 1:
                        recommendations.append(f"Same Gen: {same_gen_models[current_index + 1]['model']}")
                    else:
                        recommendations.append("Highest in Series")

                    # --- Next-gen upgrade logic ---
                    try:
                        current_gen_num = int(''.join(filter(str.isdigit, str(current_generation))))
                        next_gen_str = str(current_gen_num + 1)
                        
                        # Find potential next-gen models
                        next_gen_candidates = sorted(
                            [s for s in specs_list if str(s['generation']).startswith(next_gen_str) and s['max_throughput_mbps'] >= spec['max_throughput_mbps'] and s['max_sessions'] >= spec['max_sessions']],
                            key=lambda x: x['max_throughput_mbps']
                        )
                        
                        if next_gen_candidates:
                            recommendations.append(f"Next Gen: {next_gen_candidates[0]['model']}")

                    except (ValueError, TypeError):
                        # This handles cases where generation is not a simple number (e.g., 'N/A')
                        pass

                res['recommendation'] = " | ".join(recommendations) if recommendations else 'Sized Appropriately'

            else:
                res.update({'generation': 'N/A', 'max_sessions': 'N/A', 'max_throughput': 'N/A', 'session_util': 0, 'throughput_util': 0, 'recommendation': 'Unknown Model'})
            
            results.append(res)
        conn.close()

    return flask.render_template('advisor.html', results=results, selected_timespan=selected_timespan, alert_threshold=alert_threshold)

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    conn = get_db_connection()
    key = load_key()
    if flask.request.method == 'POST':
        # Save firewall polling settings
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", 
                     ('FW_USER', flask.request.form['username']))
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", 
                     ('POLL_INTERVAL', flask.request.form['interval']))
        if flask.request.form['password']:
            encrypted_pass = encrypt_message(flask.request.form['password'], key)
            conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", 
                         ('FW_PASSWORD', encrypted_pass))
        
        # ## This is the new logic to save Panorama settings ##
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", 
                     ('PANORAMA_HOST', flask.request.form['pano_host']))
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", 
                     ('PANORAMA_USER', flask.request.form['pano_user']))
        if flask.request.form['pano_pass']:
            encrypted_pano_pass = encrypt_message(flask.request.form['pano_pass'], key)
            conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", 
                         ('PANORAMA_PASSWORD', encrypted_pano_pass))
        
        # ** NEW: Save Alerting settings **
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                     ('ALERT_THRESHOLD', flask.request.form['alert_threshold']))
        # ** NEW: Save Data Retention settings **
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                     ('DATA_RETENTION_DAYS', flask.request.form['retention_days']))
        
        conn.commit()
        flask.flash("Settings saved successfully!")
        return flask.redirect(flask.url_for('settings'))

    # Display settings (unchanged)
    settings_data = {row['key']: row['value'] for row in conn.execute("SELECT key, value FROM settings").fetchall()}
    conn.close()
    return flask.render_template('settings.html', settings=settings_data)

@app.route('/backup_database', methods=['POST'])
def backup_database():
    """Serves the database file for download with a timestamp."""
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    return send_file(DB_FILE, as_attachment=True,
                     download_name=f'monitoring-backup-{timestamp}.db')

@app.route('/restore_database', methods=['POST'])
def restore_database():
    """Saves an uploaded database file for manual restoration."""
    if 'backup_file' not in flask.request.files:
        flask.flash('No file part in the request.', 'error')
        return flask.redirect(flask.url_for('settings'))
    file = flask.request.files['backup_file']
    if file.filename == '':
        flask.flash('No file selected for uploading.', 'warning')
        return flask.redirect(flask.url_for('settings'))
    if file and file.filename.endswith('.db'):
        # Save the file with a specific name to indicate it's a pending restore
        restore_path = os.path.join(os.path.dirname(__file__), f"{DB_FILE}.pending_restore")
        file.save(restore_path)
        flask.flash("Restore file uploaded successfully. Please stop the application, replace 'monitoring.db' with 'monitoring.db.pending_restore', and restart the application to complete the process.", "success")
    else:
        flask.flash('Invalid file type. Please upload a .db file.', 'error')
    
    return flask.redirect(flask.url_for('settings'))

def _re_evaluate_alerts(conn, alert_threshold):
    """Re-evaluates all current usage data against a given threshold and creates alerts."""
    print(f"Re-evaluating alerts with threshold: {alert_threshold}%")
    # Get all current usage and max capacity data
    firewalls_data = conn.execute("""
        SELECT 
            f.id as firewall_id, f.model,
            m.max_ssl_decrypt_sessions,
            d.*, 
            u.*
        FROM firewalls f
        LEFT JOIN firewall_models m ON f.model = m.model
        LEFT JOIN firewall_details d ON f.id = d.firewall_id
        LEFT JOIN firewall_current_usage u ON f.id = u.firewall_id
    """).fetchall()

    metrics_to_check = [
        ('Security Rules', 'current_rules', 'max_rules'), ('NAT Rules', 'current_nat_rules', 'max_nat_rules'),
        ('Address Objects', 'current_address_objects', 'max_address_objects'), ('Service Objects', 'current_service_objects', 'max_service_objects'),
        ('IPsec Tunnels', 'current_ipsec_tunnels', 'max_ipsec_tunnels'), ('Routes', 'current_routes', 'max_routes'),
        ('Multicast Routes', 'current_mroutes', 'max_mroutes'), ('ARP Entries', 'current_arp_entries', 'max_arp_entries'),
        ('BFD Sessions', 'current_bfd_sessions', 'max_bfd_sessions'), ('DNS Cache Entries', 'current_dns_cache', 'max_dns_cache'),
        ('Registered IPs (User-ID)', 'current_registered_ips', 'max_registered_ips')
    ]

    for fw in firewalls_data:
        if not fw['last_updated']: continue # Skip if no usage data
        for label, current_key, max_key in metrics_to_check:
            current_val = fw[current_key]
            max_val = fw[max_key]
            if current_val is not None and max_val is not None and max_val > 0:
                utilization = (current_val / max_val) * 100
                if utilization >= alert_threshold:
                    exists = conn.execute("SELECT 1 FROM alerts WHERE firewall_id = ? AND metric_name = ? AND acknowledged = 0", (fw['firewall_id'], label)).fetchone()
                    if not exists:
                        conn.execute("INSERT INTO alerts (firewall_id, metric_name, utilization, timestamp) VALUES (?, ?, ?, ?)",
                                     (fw['firewall_id'], label, utilization, datetime.now().isoformat()))
    conn.commit()

@app.route('/export/csv/<int:fw_id>')
def export_csv(fw_id):
    timespan = flask.request.args.get('timespan', '1h')
    conn = get_db_connection()
    fw = conn.execute('SELECT ip_address, hostname FROM firewalls WHERE id = ?', (fw_id,)).fetchone()
    if not fw:
        conn.close()
        return "Firewall not found", 404

    time_modifier = {'1h': '-1 hour', '6h': '-6 hours', '24h': '-24 hours', '7d': '-7 days'}.get(timespan, '-5 minutes')
    query_summary = f"SELECT MAX(active_sessions) as max_sessions, MAX(total_input_bps) as max_input, MAX(total_output_bps) as max_output, MAX(cpu_load) as max_cpu, MAX(dataplane_load) as max_dp FROM stats WHERE firewall_id = ? AND timestamp >= datetime('now', 'localtime', '{time_modifier}');"
    summary = conn.execute(query_summary, (fw_id,)).fetchone()
    conn.close()

    if not summary or summary['max_sessions'] is None:
        return "No data to export for this timeframe.", 404
    
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Metric', 'Peak Value'])
    cw.writerow(['Max Sessions', summary['max_sessions']])
    cw.writerow(['Highest Input', f"{summary['max_input'] / 1000000:.2f} Mbps"])
    cw.writerow(['Highest Output', f"{summary['max_output'] / 1000000:.2f} Mbps"])
    cw.writerow(['Highest CPU Load', f"{summary['max_cpu']:.2f}%"])
    cw.writerow(['Highest Dataplane Load', f"{summary['max_dp']:.2f}%"])

    output = flask.make_response(si.getvalue())
    fw_name = fw['hostname'] or fw['ip_address']
    download_name = f"{fw_name}_summary_{timespan}.csv"
    output.headers["Content-Disposition"] = f"attachment; filename={download_name}"
    output.headers["Content-type"] = "text/csv"
    return output

def _generate_pdf_worker(report_type, job_id, timespan=None, start_date=None, end_date=None):
    """Worker function to generate PDF in the background."""
    global background_task_message
    with message_lock:
        background_task_message = "Generating PDF..."
    print(f"Background PDF worker started for job {job_id}.")
    background_task_running.set()
    try:
        with app.app_context():
            try:
                # Ensure the reports directory exists
                reports_dir = os.path.join(app.static_folder, 'reports')
                os.makedirs(reports_dir, exist_ok=True)

                pdf_data = report_generator.generate_report_pdf(DB_FILE, report_type, timespan=timespan, start_date=start_date, end_date=end_date)
                if pdf_data:
                    file_path = os.path.join(reports_dir, f"{job_id}.pdf")
                    with open(file_path, 'wb') as f:
                        f.write(pdf_data)
                    with db_lock:
                        conn = get_db_connection()
                        conn.execute("UPDATE pdf_jobs SET status = 'ready' WHERE id = ?", (job_id,))
                        conn.commit()
                        conn.close()
                    print(f"PDF for job {job_id} saved to {file_path}.")
                else:
                    raise Exception("No data returned from report generator.")
            except Exception as e:
                print(f"PDF generation for job {job_id} failed: {e}")
                with db_lock:
                    conn = get_db_connection()
                    conn.execute("UPDATE pdf_jobs SET status = 'failed' WHERE id = ?", (job_id,))
                    conn.commit()
                    conn.close()
    finally:
        print(f"Background PDF worker for job {job_id} finished.")
        with message_lock:
            background_task_message = ""
        background_task_running.clear()

@app.route('/export/pdf', methods=['GET', 'POST'])
def export_pdf():
    """Kicks off a background job to generate a PDF report. Handles both predefined timespans and custom date ranges."""
    if background_task_running.is_set():
        flask.flash("A background task is already running. Please wait for it to complete.", "warning")
        return flask.redirect(flask.url_for('downloads'))

    job_id = str(uuid.uuid4())
    
    if flask.request.method == 'POST':
        # Custom date range from form
        report_type = flask.request.form.get('report_type')
        start_date = flask.request.form.get('start_date')
        end_date = flask.request.form.get('end_date')
        timespan = f"custom_{start_date}_to_{end_date}"
        download_name = f"panos-report_{report_type}_{timespan}.pdf"
        thread_args = (report_type, job_id, None, start_date, end_date)
    else: # GET request
        # Predefined timespan from buttons
        timespan = flask.request.args.get('timespan', '1h')
        report_type = flask.request.args.get('type', 'graphs_only')
        download_name = f"panos-report_{timespan}_{report_type}.pdf"
        thread_args = (report_type, job_id, timespan, None, None)

    # ** CHANGE: Store job info in the database instead of the session **
    with db_lock:
        conn = get_db_connection()
        conn.execute("INSERT INTO pdf_jobs (id, name, timestamp) VALUES (?, ?, ?)", (job_id, download_name, datetime.now().isoformat()))
        conn.commit()
        conn.close()

    # Start the background thread
    thread = threading.Thread(target=_generate_pdf_worker, args=thread_args)
    thread.start()

    return flask.redirect(flask.url_for('reports'))

@app.route('/reports')
def reports():
    """Displays a list of generated PDF reports available for download."""
    # Clean up old files
    reports_dir = os.path.join(app.static_folder, 'reports')
    jobs_to_delete_from_db = []
    if os.path.exists(reports_dir):
        for f in os.listdir(reports_dir):
            if f.endswith('.pdf'):
                file_path = os.path.join(reports_dir, f)
                if os.path.getmtime(file_path) < time.time() - 3600: # 1 hour old
                    print(f"Auto-deleting old report file: {f}")
                    os.remove(file_path)
                    jobs_to_delete_from_db.append(f.replace('.pdf', ''))
    
    if jobs_to_delete_from_db:
        with db_lock:
            conn = get_db_connection()
            conn.executemany("DELETE FROM pdf_jobs WHERE id = ?", [(job_id,) for job_id in jobs_to_delete_from_db])
            conn.commit()
            conn.close()

    # ** CHANGE: Fetch jobs from the database **
    conn = get_db_connection()
    jobs = conn.execute("SELECT * FROM pdf_jobs ORDER BY timestamp DESC").fetchall()
    conn.close()

    # Convert to list of dicts to pass to template
    jobs_list = [dict(job) for job in jobs]

    return flask.render_template('reports.html', jobs=jobs_list)

@app.route('/delete_report/<job_id>', methods=['POST'])
def delete_report(job_id):
    """Deletes a generated report file and its session entry."""
    # ** CHANGE: Delete from database and filesystem **
    with db_lock:
        conn = get_db_connection()
        conn.execute("DELETE FROM pdf_jobs WHERE id = ?", (job_id,))
        conn.commit()
        conn.close()

    # Delete the actual file
    try:
        # ** FIX: Construct an absolute path to ensure the file is found and deleted reliably **
        file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'reports', f"{job_id}.pdf")
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"Deleted report file {job_id}.pdf")
    except Exception as e:
        print(f"Error deleting report file {job_id}.pdf: {e}")
    return flask.redirect(flask.url_for('reports'))

@app.route('/firewall/<int:fw_id>', methods=['GET', 'POST'])
def firewall_detail(fw_id):
    conn = get_db_connection()

    # Handle form submission for custom date range
    if flask.request.method == 'POST':
        start_date = flask.request.form.get('start_date')
        end_date = flask.request.form.get('end_date')
        timespan = f"custom_{start_date}_to_{end_date}"
        chart_data = get_firewall_stats_for_timespan(conn, fw_id, start_date=start_date, end_date=end_date)
    else: # Default GET request
        timespan = flask.request.args.get('timespan', '1h')
        start_date = None
        end_date = None
        chart_data = get_firewall_stats_for_timespan(conn, fw_id, timespan=timespan)
    
    # Fetch all necessary firewall details, including the new hostname
    fw = conn.execute('SELECT ip_address, hostname, model, sw_version FROM firewalls WHERE id = ?', (fw_id,)).fetchone()
    
    if not fw:
        conn.close()
        return "Firewall not found", 404

    # This logic looks up the generation based on the fetched model.
    model = fw['model']
    specs_map = load_specs_from_db(conn)
    generation = specs_map.get(model, {}).get('generation', 'N/A')

    # ** NEW: Fetch detailed specs and pass them to the template **
    details = conn.execute('SELECT * FROM firewall_details WHERE firewall_id = ?', (fw_id,)).fetchone()

    summary_stats = None
    if chart_data:
        if start_date and end_date:
            where_clause = "timestamp BETWEEN ? AND ?"
            query_params = (fw_id, f"{start_date} 00:00:00", f"{end_date} 23:59:59")
        else:
            time_modifier = {'5m': '-5 minutes', '1h': '-1 hour', '6h': '-6 hours', '24h': '-24 hours', '7d': '-7 days', '30d': '-30 days'}.get(timespan, '-1 hour')
            where_clause = "timestamp >= datetime('now', 'localtime', ?)"
            query_params = (fw_id, time_modifier)
        query_summary = f"SELECT MAX(active_sessions) as max_sessions, MAX(total_input_bps) as max_input, MAX(total_output_bps) as max_output, MAX(cpu_load) as max_cpu, MAX(dataplane_load) as max_dp, MAX(memory_utilization) as max_mem FROM stats WHERE firewall_id = ? AND {where_clause};"
        summary_stats = conn.execute(query_summary, query_params).fetchone()
    full_data = {"chart_data": chart_data, "summary_data": dict(summary_stats) if summary_stats else None, "details": dict(details) if details else {}}
    conn.close()

    return flask.render_template(
        'firewall_detail.html',
        fw_id=fw_id,
        ip_address=fw['ip_address'],
        hostname=fw['hostname'],
        # Pass the corrected model and generation to the template
        model=model,
        sw_version=fw['sw_version'],
        generation=generation,
        full_data=full_data if full_data else None,
        current_timespan=timespan
    )

@app.route('/firewalls')
def manage_firewalls():
    conn = get_db_connection()
    firewalls = conn.execute('SELECT * FROM firewalls ORDER BY ip_address').fetchall()
    conn.close()
    return flask.render_template('firewalls.html', firewalls=firewalls)

@app.route('/capacity')
def capacity_dashboard():
    """Renders the new Capacity Dashboard page."""
    conn = get_db_connection()
    query = """
        SELECT
            f.id, f.hostname, f.ip_address, f.model,
            f.sw_version, m.max_ssl_decrypt_sessions,
            d.max_rules, d.max_nat_rules, d.max_address_objects, d.max_service_objects, d.max_ipsec_tunnels, d.max_routes, d.max_mroutes, d.max_arp_entries, d.max_bfd_sessions, d.max_dns_cache, d.max_registered_ips,
            u.current_rules, u.current_nat_rules, u.current_address_objects, u.current_service_objects, u.current_ipsec_tunnels, u.last_updated, u.current_routes, u.current_registered_ips,
            u.current_mroutes, u.current_arp_entries, u.current_bfd_sessions, u.current_dns_cache, u.current_ssl_decrypt_sessions
        FROM
            firewalls f
        LEFT JOIN
            firewall_models m ON f.model = m.model
        LEFT JOIN
            firewall_details d ON f.id = d.firewall_id
        LEFT JOIN
            firewall_current_usage u ON f.id = u.firewall_id
        ORDER BY
            f.hostname, f.ip_address;
    """
    firewalls_data = conn.execute(query).fetchall()
    conn.close()

    # Calculate utilization percentages
    results = []
    for fw in firewalls_data:
        fw_dict = dict(fw)
        fw_dict['util_rules'] = (fw['current_rules'] / fw['max_rules'] * 100) if fw['current_rules'] is not None and fw['max_rules'] else 0
        fw_dict['util_nat_rules'] = (fw['current_nat_rules'] / fw['max_nat_rules'] * 100) if fw['current_nat_rules'] is not None and fw['max_nat_rules'] else 0
        fw_dict['util_address'] = (fw['current_address_objects'] / fw['max_address_objects'] * 100) if fw['current_address_objects'] is not None and fw['max_address_objects'] else 0
        fw_dict['util_service'] = (fw['current_service_objects'] / fw['max_service_objects'] * 100) if fw['current_service_objects'] is not None and fw['max_service_objects'] else 0
        fw_dict['util_ipsec'] = (fw['current_ipsec_tunnels'] / fw['max_ipsec_tunnels'] * 100) if fw['current_ipsec_tunnels'] is not None and fw['max_ipsec_tunnels'] else 0
        fw_dict['util_routes'] = (fw['current_routes'] / fw['max_routes'] * 100) if fw['current_routes'] is not None and fw['max_routes'] else 0
        fw_dict['util_mroutes'] = (fw['current_mroutes'] / fw['max_mroutes'] * 100) if fw['current_mroutes'] is not None and fw['max_mroutes'] else 0
        fw_dict['util_arp'] = (fw['current_arp_entries'] / fw['max_arp_entries'] * 100) if fw['current_arp_entries'] is not None and fw['max_arp_entries'] else 0
        fw_dict['util_bfd'] = (fw['current_bfd_sessions'] / fw['max_bfd_sessions'] * 100) if fw['current_bfd_sessions'] is not None and fw['max_bfd_sessions'] else 0
        fw_dict['util_dns_cache'] = (fw['current_dns_cache'] / fw['max_dns_cache'] * 100) if fw['current_dns_cache'] is not None and fw['max_dns_cache'] else 0
        fw_dict['util_registered_ips'] = (fw['current_registered_ips'] / fw['max_registered_ips'] * 100) if fw['current_registered_ips'] is not None and fw['max_registered_ips'] else 0
        fw_dict['util_ssl_decrypt_sessions'] = (fw['current_ssl_decrypt_sessions'] / fw['max_ssl_decrypt_sessions'] * 100) if fw['current_ssl_decrypt_sessions'] is not None and fw['max_ssl_decrypt_sessions'] else 0
        results.append(fw_dict)
    
    return flask.render_template('capacity.html', firewalls=results)

@app.route('/alerts')
def alerts():
    """Displays active, unacknowledged alerts."""
    conn = get_db_connection()
    settings = {row['key']: row['value'] for row in conn.execute("SELECT key, value FROM settings").fetchall()}
    alert_threshold = settings.get('ALERT_THRESHOLD', '80')
    query = """
        SELECT a.id, a.metric_name, a.utilization, a.timestamp, f.hostname, f.ip_address
        FROM alerts a
        JOIN firewalls f ON a.firewall_id = f.id
        WHERE a.acknowledged = 0
        ORDER BY a.timestamp DESC;
    """
    active_alerts = conn.execute(query).fetchall()
    conn.close()
    return flask.render_template('alerts.html', alerts=active_alerts, alert_threshold=alert_threshold)

@app.route('/acknowledge_alerts', methods=['POST'])
def acknowledge_alerts():
    """Marks multiple alerts as acknowledged based on checkbox selections."""
    alert_ids_to_ack = flask.request.form.getlist('alert_ids')
    if alert_ids_to_ack:
        conn = get_db_connection()
        # Prepare a list of tuples for executemany
        conn.executemany("UPDATE alerts SET acknowledged = 1 WHERE id = ?", [(id,) for id in alert_ids_to_ack])
        conn.commit()
        conn.close()
        flask.flash(f"Acknowledged {len(alert_ids_to_ack)} alert(s).", "success")
    return flask.redirect(flask.url_for('alerts'))

@app.route('/toggle_theme', methods=['POST'])
def toggle_theme():
    """Saves the selected theme to the database."""
    data = flask.request.get_json()
    theme = data.get('theme')
    if theme in ['light', 'dark']:
        conn = get_db_connection()
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", ('THEME', theme))
        conn.commit()
        conn.close()
        return flask.jsonify({'status': 'success', 'theme': theme})
    return flask.jsonify({'status': 'error', 'message': 'Invalid theme'}), 400

@app.route('/add_firewall', methods=['POST'])
def add_firewall():
    ip_address = flask.request.form['ip_address']
    if ip_address:
        conn = get_db_connection()
        try: conn.execute('INSERT INTO firewalls (ip_address) VALUES (?)', (ip_address,)); conn.commit()
        except sqlite3.IntegrityError: pass
        conn.close()
    return flask.redirect(flask.url_for('manage_firewalls'))

@app.route('/import_firewalls', methods=['POST'])
def import_firewalls():
    file = flask.request.files['file']
    if file and file.filename.endswith('.txt'):
        content = file.read().decode('utf-8').splitlines()
        conn = get_db_connection()
        for ip in content:
            ip = ip.strip()
            if ip and not ip.startswith('#'):
                try: conn.execute('INSERT INTO firewalls (ip_address) VALUES (?)', (ip,));
                except sqlite3.IntegrityError: pass
        conn.commit()
        conn.close()
    return flask.redirect(flask.url_for('manage_firewalls'))

def _import_from_panorama_worker():
    """Worker function to run the Panorama import in a background thread."""
    global background_task_message
    with message_lock:
        background_task_message = "Importing from Panorama..."
    background_task_running.set()
    try:
        print("Background Panorama import worker started.")
        with app.app_context():
            key = load_key()
            conn = get_db_connection()
            settings = {row['key']: row['value'] for row in conn.execute("SELECT key, value FROM settings").fetchall()}
            pano_host = settings.get('PANORAMA_HOST')
            pano_user = settings.get('PANORAMA_USER')
            encrypted_pass = settings.get('PANORAMA_PASSWORD')

            if not all([pano_host, pano_user, encrypted_pass]):
                print("Panorama import failed: Settings are incomplete.")
                conn.close()
                return

            pano_pass = decrypt_message(encrypted_pass, key)
            
            try:
                api_params = {'type': 'keygen', 'user': pano_user, 'password': pano_pass}
                response = requests.get(f"https://{pano_host}/api/", params=api_params, verify=False, timeout=10)
                response.raise_for_status()
                tree = ET.fromstring(response.content)
                api_key = tree.find('.//key')
                if api_key is None or not api_key.text:
                    raise Exception("Failed to get API key from Panorama. Check credentials.")

                cmd = "<show><devices><connected></connected></devices></show>"
                response = requests.get(f"https://{pano_host}/api/?type=op&cmd={cmd}&key={api_key.text}", verify=False, timeout=20)
                response.raise_for_status()

                device_tree = ET.fromstring(response.content)
                ips_to_import = [dev.findtext('ip-address') for dev in device_tree.findall('.//devices/entry')]
                
                with db_lock:
                    for ip in ips_to_import:
                        if ip:
                            conn.execute('INSERT OR IGNORE INTO firewalls (ip_address) VALUES (?)', (ip,))
                    conn.commit()
                print(f"Panorama import successful. Processed {len(ips_to_import)} devices.")
            except Exception as e:
                print(f"Error during Panorama import: {e}")
            finally:
                conn.close()
    finally:
        print("Background Panorama import worker finished.")
        with message_lock:
            background_task_message = ""
        background_task_running.clear()

@app.route('/import_from_panorama', methods=['POST'])
def import_from_panorama():
    if background_task_running.is_set():
        flask.flash("A background task is already running. Please wait for it to complete.", "warning")
        return flask.redirect(flask.url_for('manage_firewalls'))
    
    thread = threading.Thread(target=_import_from_panorama_worker)
    thread.start()
    return flask.redirect(flask.url_for('manage_firewalls'))

@app.route('/delete_firewalls', methods=['POST'])
def delete_firewalls():
    """Deletes multiple firewalls based on checkbox selections."""
    fw_ids_to_delete = flask.request.form.getlist('firewall_ids')
    if fw_ids_to_delete:
        conn = get_db_connection()
        conn.executemany("DELETE FROM firewalls WHERE id = ?", [(id,) for id in fw_ids_to_delete])
        conn.commit()
        conn.close()
        flask.flash(f"Deleted {len(fw_ids_to_delete)} firewall(s).", "success")
    else:
        flask.flash("No firewalls selected for deletion.", "warning")
    return flask.redirect(flask.url_for('manage_firewalls'))

# --- NEW: Routes for Managing Firewall Models ---
@app.route('/model_specs')
def model_specs():
    conn = get_db_connection()
    models = conn.execute('SELECT * FROM firewall_models ORDER BY generation, max_sessions, max_throughput_mbps').fetchall()
    conn.close()
    return flask.render_template('models.html', models=models)

@app.route('/add_model', methods=['POST'])
def add_model():
    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO firewall_models (model, generation, max_sessions, max_throughput_mbps, max_ssl_decrypt_sessions) VALUES (?, ?, ?, ?, ?)",
            (flask.request.form['model'], flask.request.form['generation'], flask.request.form['max_sessions'], flask.request.form['max_throughput'], flask.request.form['max_ssl_decrypt_sessions'])
        )
        conn.commit()
        flask.flash(f"Model '{flask.request.form['model']}' added successfully.", "success")
    except sqlite3.IntegrityError:
        flask.flash(f"Error: Model '{flask.request.form['model']}' already exists.", "error")
    except Exception as e:
        flask.flash(f"An error occurred: {e}", "error")
    finally:
        conn.close()
    return flask.redirect(flask.url_for('model_specs'))

@app.route('/update_model', methods=['POST'])
def update_model():
    """Updates an existing firewall model's specifications."""
    conn = get_db_connection()
    try:
        conn.execute(
            "UPDATE firewall_models SET generation = ?, max_sessions = ?, max_throughput_mbps = ?, max_ssl_decrypt_sessions = ? WHERE model = ?",
            (flask.request.form['generation'], flask.request.form['max_sessions'], flask.request.form['max_throughput'], flask.request.form['max_ssl_decrypt_sessions'], flask.request.form['model'])
        )
        conn.commit()
        flask.flash(f"Model '{flask.request.form['model']}' updated successfully.", "success")
    except Exception as e:
        flask.flash(f"An error occurred while updating the model: {e}", "error")
    finally:
        conn.close()
    return flask.redirect(flask.url_for('model_specs'))

@app.route('/delete_models', methods=['POST'])
def delete_models():
    """Deletes multiple firewall models based on checkbox selections."""
    model_names_to_delete = flask.request.form.getlist('model_names')
    if model_names_to_delete:
        conn = get_db_connection()
        conn.executemany("DELETE FROM firewall_models WHERE model = ?", [(name,) for name in model_names_to_delete])
        conn.commit()
        conn.close()
        flask.flash(f"Deleted {len(model_names_to_delete)} model(s).", "success")
    else:
        flask.flash("No models selected for deletion.", "warning")
    return flask.redirect(flask.url_for('model_specs'))

def _refresh_specs_worker():
    """Worker function to run the spec refresh in a background thread."""
    global background_task_message
    with message_lock:
        background_task_message = "Refreshing specs..."
    background_task_running.set()
    try:
        print("Background spec refresh worker started.")
        with app.app_context(): # Need app context to access flask.flash and url_for
            key = load_key()
            conn = get_db_connection()
            settings_rows = conn.execute("SELECT key, value FROM settings").fetchall()
            settings = {row['key']: row['value'] for row in settings_rows}
            fw_user = settings.get('FW_USER')
            encrypted_pass = settings.get('FW_PASSWORD')

            if not fw_user or not encrypted_pass:
                print("Spec Refresh Worker: Credentials not set.")
                conn.close()
                return

            fw_password = decrypt_message(encrypted_pass, key)
            firewalls = conn.execute('SELECT id, ip_address FROM firewalls').fetchall()
            
            if not firewalls:
                conn.close()
                return

            hosts_to_poll = [fw['ip_address'] for fw in firewalls]
            init_tasks = [(host, fw_user, fw_password) for host in hosts_to_poll]
            api_keys = {}
            try:
                with multiprocessing.Pool(processes=len(init_tasks)) as pool:
                    for res in pool.map(get_api_key, init_tasks):
                        if res['status'] == 'success':
                            api_keys[res['host']] = res['api_key']
            except Exception as e:
                print(f"Spec Refresh Worker Error: {e}")
                conn.close()
                return

            with db_lock:
                for fw in firewalls:
                    if fw['ip_address'] in api_keys:
                        parse_and_store_fw_details(conn, fw['id'], api_keys[fw['ip_address']])
                
                # ** NEW: Re-evaluate alerts since max capacities may have changed **
                alert_threshold = int(settings.get('ALERT_THRESHOLD', 80))
                _re_evaluate_alerts(conn, alert_threshold)

                conn.commit()
            conn.close()
    finally:
        print("Background spec refresh worker finished.")
        with message_lock:
            background_task_message = ""
        background_task_running.clear()

@app.route('/refresh_specs', methods=['POST'])
def refresh_specs():
    """Manually triggers a refresh of the detailed capacity specs for all firewalls."""
    if background_task_running.is_set():
        flask.flash("A background task is already running. Please wait for it to complete.", "warning")
        return flask.redirect(flask.request.referrer or flask.url_for('index'))

    print("Manual spec refresh triggered.")
    key = load_key()
    conn = get_db_connection()
    settings_rows = conn.execute("SELECT key, value FROM settings").fetchall()
    conn.close()
    if not settings_rows or not settings_rows[0]:
        flask.flash("Cannot refresh specs. Firewall credentials are not set in Settings.", "error")
        return flask.redirect(flask.request.referrer or flask.url_for('index'))

    # ** NEW: Start the worker in a background thread **
    thread = threading.Thread(target=_refresh_specs_worker)
    thread.start()
    return flask.redirect(flask.request.referrer or flask.url_for('index'))

def _refresh_capacity_worker():
    """Worker function to run the capacity refresh in a background thread."""
    global background_task_message
    with message_lock:
        background_task_message = "Refreshing capacity..."
    background_task_running.set()
    try:
        print("Background capacity refresh worker started.")
        with app.app_context():
            key = load_key()
            conn = get_db_connection()
            settings_rows = conn.execute("SELECT key, value FROM settings").fetchall()
            settings = {row['key']: row['value'] for row in settings_rows}
            fw_user = settings.get('FW_USER')
            encrypted_pass = settings.get('FW_PASSWORD')

            if not fw_user or not encrypted_pass:
                print("Capacity Refresh Worker: Credentials not set.")
                conn.close()
                return

            fw_password = decrypt_message(encrypted_pass, key)
            firewalls = conn.execute('SELECT id, ip_address FROM firewalls').fetchall()
            
            if not firewalls:
                conn.close()
                return

            hosts_to_poll = [fw['ip_address'] for fw in firewalls]
            init_tasks = [(host, fw_user, fw_password) for host in hosts_to_poll]
            api_keys = {}
            try:
                with multiprocessing.Pool(processes=len(init_tasks)) as pool:
                    for res in pool.map(get_api_key, init_tasks):
                        if res['status'] == 'success':
                            api_keys[res['host']] = res['api_key']
            except Exception as e:
                print(f"Capacity Refresh Worker Error: {e}")
                conn.close()
                return

            with db_lock:
                # ** FIX: Join with firewall_models to get all max capacity values in one go **
                details_map = {row['firewall_id']: dict(row) for row in conn.execute("SELECT fd.*, fm.max_ssl_decrypt_sessions FROM firewall_details fd JOIN firewalls f ON f.id = fd.firewall_id LEFT JOIN firewall_models fm ON f.model = fm.model").fetchall()}
                for fw in firewalls:
                    if fw['ip_address'] in api_keys:
                        usage_data = poll_current_usage(conn, fw['id'], fw['ip_address'], api_keys[fw['ip_address']])
                        if usage_data:
                            # ** FIX: Use the full, correct INSERT statement **
                            conn.execute("""
                                INSERT OR REPLACE INTO firewall_current_usage 
                                (firewall_id, last_updated, current_rules, current_nat_rules, current_address_objects, current_service_objects, current_ipsec_tunnels, current_routes, current_mroutes, current_arp_entries, current_bfd_sessions, current_dns_cache, current_registered_ips, current_ssl_decrypt_sessions) 
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) 
                            """, (fw['id'], datetime.now().isoformat(sep=' ', timespec='microseconds'), usage_data.get('rules'), usage_data.get('nat-rules'), usage_data.get('address'), usage_data.get('service'), usage_data.get('ipsec'), usage_data.get('routes', 0), usage_data.get('mroutes'), usage_data.get('arp'), usage_data.get('bfd'), usage_data.get('dns_cache'), usage_data.get('registered_ips'), usage_data.get('ssl_decrypt_sessions')))
                            
                # After polling all firewalls, re-evaluate alerts with the latest data
                alert_threshold = int(settings.get('ALERT_THRESHOLD', 80))
                _re_evaluate_alerts(conn, alert_threshold)

                conn.commit()
            conn.close()
    finally:
        print("Background capacity refresh worker finished.")
        with message_lock:
            background_task_message = ""
        background_task_running.clear()

@app.route('/refresh_capacity', methods=['POST'])
def refresh_capacity():
    """Manually triggers a refresh of the current object usage for all firewalls."""
    if background_task_running.is_set():
        flask.flash("A background task is already running. Please wait for it to complete.", "warning")
        return flask.redirect(flask.url_for('capacity_dashboard'))

    print("Manual capacity usage refresh triggered.")
    key = load_key()
    conn = get_db_connection()
    settings_rows = conn.execute("SELECT key, value FROM settings").fetchall()
    settings = {row['key']: row['value'] for row in settings_rows}
    conn.close()
    if not settings.get('FW_USER') or not settings.get('FW_PASSWORD'):
        flask.flash("Cannot refresh capacity. Firewall credentials are not set in Settings.", "error")
        return flask.redirect(flask.url_for('capacity_dashboard'))

    # ** NEW: Start the worker in a background thread **
    thread = threading.Thread(target=_refresh_capacity_worker)
    thread.start()
    return flask.redirect(flask.url_for('capacity_dashboard'))

@app.route('/trigger_poll', methods=['POST'])
def trigger_poll():
    """Sets an event to trigger the background poller immediately."""
    if not background_task_running.is_set():
        global background_task_message
        with message_lock:
            background_task_message = "Polling data..."
        background_task_running.set()
        manual_poll_event.set()
    return flask.redirect(flask.url_for('index'))

def poll_current_usage(conn, firewall_id, host, api_key):
    """Polls a single firewall for its current object counts."""
    commands = {
        'config': {
            'rules': "/config/devices/entry[@name='localhost.localdomain']/vsys/entry/rulebase/security/rules",
            'nat-rules': "/config/devices/entry[@name='localhost.localdomain']/vsys/entry/rulebase/nat/rules",
            'address': "/config/devices/entry[@name='localhost.localdomain']/vsys/entry/address",
            'service': "/config/devices/entry[@name='localhost.localdomain']/vsys/entry/service",
            'ipsec': "/config/devices/entry[@name='localhost.localdomain']/network/tunnel/ipsec"
        },
        'op': {
            'arp': ("<show><arp><entry name='all'/></arp></show>", './/entries/entry'),
            'dns_cache': ("<show><dns-proxy><cache><all/></cache></dns-proxy></show>", './/entry'),
            'registered_ips': ("<show><user><ip-user-mapping><all></all></ip-user-mapping></user></show>", './/entry'),
            'ssl_decrypt_sessions': ("<show><session><all><filter><ssl-decrypt>yes</ssl-decrypt><count>yes</count></filter></all></session></show>", './/result')
        }
    }
    usage_data = {}
    # Poll config-based stats
    for key, xpath in commands['config'].items():
        try:
            params = {'type': 'config', 'action': 'get', 'key': api_key, 'xpath': xpath}
            response = requests.get(f"https://{host}/api/", params=params, verify=False, timeout=10)
            response.raise_for_status()
            root = ET.fromstring(response.content)
            entries = root.findall('.//entry')
            usage_data[key] = len(entries)
        except Exception as e:
            print(f"Error polling config stat '{key}' for {host}: {e}")
            usage_data[key] = None # Mark as None on error

    # ** NEW: Conditional route polling **
    try:
        adv_routing_row = conn.execute("SELECT advance_routing_enabled FROM firewall_details WHERE firewall_id = ?", (firewall_id,)).fetchone()
        adv_routing_enabled = adv_routing_row['advance_routing_enabled'] if adv_routing_row else False

        if adv_routing_enabled:
            # Use advanced routing command
            cmd = '<show><advanced-routing><route></route></advanced-routing></show>'
            params = {'type': 'op', 'cmd': cmd, 'key': api_key}
            response = requests.get(f"https://{host}/api/", params=params, verify=False, timeout=15)
            response.raise_for_status()
            root = ET.fromstring(response.content)
            json_text = root.findtext('.//result/json')
            if json_text:
                import json
                route_data = json.loads(json_text)
                total_routes = sum(len(route_list) for vrf in route_data.values() for route_list in vrf.values())
                usage_data['routes'] = total_routes
        else:
            # Use standard routing command
            cmd = '<show><routing><route></route></routing></show>'
            params = {'type': 'op', 'cmd': cmd, 'key': api_key}
            response = requests.get(f"https://{host}/api/", params=params, verify=False, timeout=15)
            response.raise_for_status()
            root = ET.fromstring(response.content)
            usage_data['routes'] = len(root.findall('.//routing-table/ip/entry'))
    except Exception as e:
        print(f"Error polling route stat for {host}: {e}")
        usage_data['routes'] = None

    # ** NEW: Conditional multicast route polling **
    try:
        # We can reuse the adv_routing_enabled flag from the previous check
        if adv_routing_enabled:
            # Use advanced routing command for multicast
            cmd = '<show><advanced-routing><multicast><route></route></multicast></advanced-routing></show>'
            params = {'type': 'op', 'cmd': cmd, 'key': api_key}
            response = requests.get(f"https://{host}/api/", params=params, verify=False, timeout=15)
            response.raise_for_status()
            root = ET.fromstring(response.content)
            json_text = root.findtext('.//result/json')
            if json_text:
                import json
                mroute_data = json.loads(json_text)
                # The structure is likely similar to unicast, so we sum the lengths of the route lists
                total_mroutes = sum(len(route_list) for vrf in mroute_data.values() for route_list in vrf.values())
                usage_data['mroutes'] = total_mroutes
        else:
            # Use standard multicast routing command
            cmd = '<show><routing><multicast><route/></multicast></routing></show>'
            params = {'type': 'op', 'cmd': cmd, 'key': api_key}
            response = requests.get(f"https://{host}/api/", params=params, verify=False, timeout=15)
            response.raise_for_status()
            root = ET.fromstring(response.content)
            # This command returns a CDATA block, so we count the lines.
            cdata_text = root.findtext('.//result')
            # Subtract 1 for the "Flags:" header line.
            usage_data['mroutes'] = max(0, len(cdata_text.strip().split('\n')) - 1) if cdata_text else 0
    except Exception as e:
        print(f"Error polling multicast route stat for {host}: {e}")
        usage_data['mroutes'] = None

    # ** FIX: Re-introduce conditional BFD session polling **
    try:
        fw_row = conn.execute("SELECT sw_version FROM firewalls WHERE id = ?", (firewall_id,)).fetchone()
        sw_version_str = fw_row['sw_version'] if fw_row else '0.0.0'
        major_version = int(sw_version_str.split('.')[0])

        if major_version >= 11:
            if adv_routing_enabled:
                bfd_cmd = '<show><advanced-routing><bfd><summary/></bfd></advanced-routing></show>'
            else:
                bfd_cmd = '<show><routing><bfd><summary/></bfd></routing></show>'
            
            params = {'type': 'op', 'cmd': bfd_cmd, 'key': api_key}
            response = requests.get(f"https://{host}/api/", params=params, verify=False, timeout=15)
            response.raise_for_status()
            root = ET.fromstring(response.content)
            usage_data['bfd'] = len(root.findall('.//result/entry'))
        else:
            # BFD summary command not supported on older versions
            usage_data['bfd'] = 0
    except Exception as e:
        print(f"Error polling BFD stat for {host}: {e}")
        usage_data['bfd'] = None
    
    # Poll op-based stats
    for key, (cmd, find_path) in commands['op'].items():
        try:
            params = {'type': 'op', 'cmd': cmd, 'key': api_key}
            if key == 'dns_cache':
                # Special handling for DNS cache command which returns text
                response = requests.get(f"https://{host}/api/", params=params, verify=False, timeout=15)
                response.raise_for_status()
                root = ET.fromstring(response.content)
                total_dns_entries = 0
                # The result is a series of <msg> tags, not structured XML entries
                for msg_tag in root.findall('.//result/msg'):
                    if msg_tag.text and msg_tag.text.strip().startswith('entries:'):
                        parts = msg_tag.text.strip().split(':')
                        if len(parts) > 1 and parts[1].strip().isdigit():
                            total_dns_entries += int(parts[1].strip())
                usage_data[key] = total_dns_entries
            elif key == 'ssl_decrypt_sessions':
                # Special handling for SSL decrypt count which returns a CDATA block
                response = requests.get(f"https://{host}/api/", params=params, verify=False, timeout=15)
                response.raise_for_status()
                root = ET.fromstring(response.content)
                cdata_text = root.findtext(find_path)
                count = 0
                if cdata_text and 'Number of sessions that match filter:' in cdata_text:
                    parts = cdata_text.split(':')
                    if len(parts) > 1 and parts[1].strip().isdigit():
                        count = int(parts[1].strip())
                usage_data[key] = count
            else:
                response = requests.get(f"https://{host}/api/", params=params, verify=False, timeout=15)
                response.raise_for_status()
                root = ET.fromstring(response.content)
                entries = root.findall(find_path)
                usage_data[key] = len(entries)
        except Exception as e:
            print(f"Error polling op stat '{key}' for {host}: {e}")
            usage_data[key] = None
    return usage_data

# --- Background Polling Logic ---
def get_api_key(args):
    host, user, password = args
    base_url = f"https://{host}/api/"
    api_params = {'type': 'keygen', 'user': user, 'password': password}
    try:
        response = requests.get(base_url, params=api_params, verify=False, timeout=10)
        response.raise_for_status()
        tree = ET.fromstring(response.content)
        key_element = tree.find('.//key')
        if key_element is not None and key_element.text: return {'status': 'success', 'host': host, 'api_key': key_element.text}
        else:
            error_msg = tree.findtext('.//line') or "Authentication failed"
            return {'status': 'error', 'host': host, 'error_message': error_msg}
    except requests.exceptions.RequestException as e:
        return {'status': 'error', 'host': host, 'error_message': str(e)}

def parse_and_store_fw_details(conn, firewall_id, api_key):
    """Fetches, parses, and stores detailed firewall capacity specs."""
    host = conn.execute('SELECT ip_address FROM firewalls WHERE id = ?', (firewall_id,)).fetchone()['ip_address']
    cmd = "<show><system><state><filter>cfg.general.*</filter></state></system></show>"
    try:
        response = requests.get(f"https://{host}/api/?type=op&cmd={cmd}&key={api_key}", verify=False, timeout=15)
        response.raise_for_status()
        root = ET.fromstring(response.content)
        cdata = root.find('.//result').text

        if not cdata: return

        # Map raw config names to database column names
        spec_map = {
            'cfg.general.max-session': 'max_sessions',
            'cfg.general.max-policy-rule': 'max_rules',
            'cfg.general.max-nat-policy-rule': 'max_nat_rules',
            'cfg.general.max-ssl-policy-rule': 'max_ssl_decrypt_rules',
            'cfg.general.max-qos-policy-rule': 'max_qos_rules',
            'cfg.general.max-pbf-policy-rule': 'max_pbf_rules',
            'cfg.general.max-dos-policy-rule': 'max_dos_rules',
            'cfg.general.max-zone': 'max_zones',
            'cfg.general.max-vsys': 'max_vsys',
            'cfg.general.max-vrouter': 'max_virtual_routers',
            'cfg.general.max-vlan': 'max_vlans',
            'cfg.general.max-ike-peers': 'max_ike_peers',
            'cfg.general.max-tunnel': 'max_ipsec_tunnels',
            'cfg.general.advance-routing-enabled': 'advance_routing_enabled',
            'cfg.general.max-ssl-tunnel': 'max_ssl_tunnels',
            'cfg.general.max-address-per-group': 'max_addr_per_group',
            'cfg.general.max-cert-cache-entries': 'max_cert_cache',
            'cfg.general.max-dns-cache': 'max_dns_cache',
            'cfg.general.max-ip6addrtbl': 'max_ipv6_addrs',
            'cfg.general.max-mac': 'max_mac_addrs',
            'cfg.general.max-profile': 'max_security_profiles',
            'cfg.general.max-url-pattern': 'max_url_patterns',
            'cfg.general.max-vwire': 'max_vwires',
            'cfg.general.max-hip': 'max_hip_objects',
            'cfg.general.max-blacklist': 'max_custom_signatures',
            'cfg.general.max-ifnet': 'max_interfaces',
            'cfg.general.max-bfd-session': 'max_bfd_sessions',
            'cfg.general.max-sdwan-policy-rule': 'max_sdwan_rules',
            'cfg.general.max-mroute': 'max_mroutes',
            'cfg.general.max-schedule': 'max_schedules',
            'cfg.general.max-edl-objs': 'max_edl_objects',
            'cfg.general.max-registered-ip-address': 'max_registered_ips',
            'cfg.general.max-tsagents': 'max_ts_agents',
            'cfg.general.max-proxy-session': 'max_proxy_sessions',
            'cfg.general.max-auth-policy-rule': 'max_auth_rules',
            'cfg.general.max-address': 'max_address_objects',
            'cfg.general.max-address-group': 'max_address_groups',
            'cfg.general.max-service': 'max_service_objects',
            'cfg.general.max-service-group': 'max_service_groups',
            'cfg.general.max-route': 'max_routes',
            'cfg.general.max-arp': 'max_arp_entries'
        }
        
        parsed_data = {}
        for line in cdata.strip().split('\n'):
            key, value = line.split(':', 1)
            key = key.strip()
            if key in spec_map:
                db_column = spec_map[key]
                val_str = value.strip()
                try:
                    if val_str.lower() == 'true':
                        parsed_data[db_column] = 1
                    elif val_str.lower() == 'false':
                        parsed_data[db_column] = 0
                    else:
                        parsed_data[db_column] = int(val_str, 16) if val_str.startswith('0x') else int(val_str)
                except (ValueError, TypeError):
                    pass # Ignore values that can't be converted to an integer (like 'True' or lists)

        if parsed_data:
            columns, values = zip(*parsed_data.items())
            conn.execute(f"INSERT OR REPLACE INTO firewall_details (firewall_id, {', '.join(columns)}) VALUES (?, {', '.join(['?'] * len(values))})", (firewall_id, *values))
    except Exception as e:
        print(f"Could not fetch/parse details for {host}: {e}")

def poll_single_firewall(args):
    """Worker function to poll metrics from a single firewall."""
    host, api_key, previous_state = args
    try:
        # API Calls
        session_xml = requests.get(f"https://{host}/api/?type=op&key={api_key}&cmd=<show><session><info/></session></show>", verify=False, timeout=15).content
        if_counter_xml = requests.get(f"https://{host}/api/?type=op&key={api_key}&cmd=<show><counter><interface>all</interface></counter></show>", verify=False, timeout=15).content
        mem_xml = requests.get(f"https://{host}/api/?type=op&key={api_key}&cmd=<show><system><resources/></system></show>", verify=False, timeout=15).content
        # ** NEW: Use the 'minute last 1' command for Dataplane CPU **
        cpu_dp_xml = requests.get(f"https://{host}/api/?type=op&key={api_key}&cmd=<show><running><resource-monitor><minute><last>1</last></minute></resource-monitor></running></show>", verify=False, timeout=15).content
        ssl_decrypt_xml = requests.get(f"https://{host}/api/?type=op&key={api_key}&cmd=<show><session><all><filter><ssl-decrypt>yes</ssl-decrypt></filter></all></session></show>", verify=False, timeout=15).content
        
        # Process Session info
        session_tree = ET.fromstring(session_xml)
        active_sessions = int(session_tree.find('.//num-active').text or 0)
        
        # Process SSL Decrypt Session info by counting entries
        ssl_decrypt_tree = ET.fromstring(ssl_decrypt_xml)
        ssl_decrypt_sessions = len(ssl_decrypt_tree.findall('.//result/entry'))

        # --- NEW: Initialize variables ---
        memory_utilization = 0.0
        cpu_load = 0.0
        dataplane_load = 0.0

        # --- NEW: Get Management CPU from 'show system resources' ---
        cdata = ET.fromstring(mem_xml).findtext('.//result')
        if cdata:
            # ** NEW: Use regex to reliably parse the 'us' value for Management CPU **
            # This regex is designed to be flexible with spacing and capture the user space CPU percentage.
            match = re.search(r"%Cpu\(s\):\s+([\d\.]+) us", cdata)
            if match:
                try:
                    cpu_load = float(match.group(1))
                except (ValueError, IndexError):
                    pass # Could not parse CPU value

        cdata = ET.fromstring(mem_xml).findtext('.//result')

        # --- NEW: Parse memory from 'show system resources' (top) output ---
        if cdata:
            # Find the memory line, which can start with "KiB Mem" or "MiB Mem"
            mem_line = next((line for line in cdata.split('\n') if 'KiB Mem' in line or 'MiB Mem' in line), None)
            if mem_line:
                parts = mem_line.split()
                try:
                    # Find 'total' and 'used' values by index
                    total_mem_index = parts.index('total,') - 1
                    used_mem_index = parts.index('used,') - 1
                    total_mem = float(parts[total_mem_index])
                    used_mem = float(parts[used_mem_index])
                    if total_mem > 0:
                        memory_utilization = (used_mem / total_mem) * 100
                except (ValueError, IndexError):
                    pass # Could not parse memory line

        # --- NEW: Get Dataplane CPU from 'show running resource-monitor' ---
        core_loads = []
        data_processors_node = ET.fromstring(cpu_dp_xml).find('.//data-processors')
        if data_processors_node is not None:
            for dp_node in data_processors_node:
                # The command gives us the <minute> block directly.
                # We parse the cpu-load-average from it.
                cpu_avg_node = dp_node.find('.//minute/cpu-load-average')
                if cpu_avg_node is not None:
                    for core_entry in cpu_avg_node.findall('entry'):
                        value_str = core_entry.findtext('value')
                        if value_str:
                            # The value should be a single integer representing the average.
                            core_loads.append(int(value_str))

        if core_loads:
            # DP load is the average across all cores
            dataplane_load = sum(core_loads) / len(core_loads)

        # Process Throughput info
        current_timestamp = time.time()
        current_counters = {entry.find('name').text: {'ibytes': int(entry.find('ibytes').text), 'obytes': int(entry.find('obytes').text)} for entry in ET.fromstring(if_counter_xml).findall('.//entry')}
        total_in_bps, total_out_bps = 0.0, 0.0
        if previous_state and previous_state['counters']:
            time_delta = current_timestamp - previous_state['timestamp']
            for if_name, counters in current_counters.items():
                if if_name in previous_state['counters'] and time_delta > 0:
                    prev = previous_state['counters'][if_name]
                    total_in_bps += ((counters['ibytes'] - prev['ibytes']) * 8) / time_delta
                    total_out_bps += ((counters['obytes'] - prev['obytes']) * 8) / time_delta
        
        return {
            "status": "success", "host": host,
            "data": { 
                "active_sessions": active_sessions, 
                "ssl_decrypt_sessions": ssl_decrypt_sessions,
                "total_input_bps": total_in_bps, 
                "total_output_bps": total_out_bps,
                "cpu_load": cpu_load,
                "dataplane_load": dataplane_load,
                "memory_utilization": memory_utilization
            },
            "new_state": {'counters': current_counters, 'timestamp': current_timestamp}
        }
    except Exception as e:
        print(f"Polling error for {host}: {e}")
        return {"status": "error", "host": host, "new_state": previous_state}

def background_worker_loop():
    print("🚀 Background worker started.")
    firewall_states = {} 
    key = load_key()
    while True:
        # --- SETUP FOR POLLING CYCLE ---
        conn = get_db_connection()
        settings_rows = conn.execute("SELECT key, value FROM settings").fetchall()
        settings = {row['key']: row['value'] for row in settings_rows}
        fw_user = settings.get('FW_USER')
        encrypted_pass = settings.get('FW_PASSWORD')
        poll_interval = int(settings.get('POLL_INTERVAL', 30))
        retention_days = int(settings.get('DATA_RETENTION_DAYS', 90))

        if not fw_user or not encrypted_pass:
            print("Worker: Credentials not set in database. Waiting...")
            conn.close()
            time.sleep(poll_interval)
            continue
            
        fw_password = decrypt_message(encrypted_pass, key)
        firewalls = conn.execute('SELECT id, ip_address, hostname, model, sw_version FROM firewalls').fetchall()
        hosts_to_poll = [fw['ip_address'] for fw in firewalls]

        if not hosts_to_poll:
            print("Worker: No firewalls in DB to poll. Waiting...")
            conn.close()
            time.sleep(poll_interval)
            continue

        # --- GET API KEYS & DISCOVER MODELS ---
        init_tasks = [(host, fw_user, fw_password) for host in hosts_to_poll]
        api_keys = {}
        try:
            with multiprocessing.Pool(processes=len(init_tasks)) as pool:
                for res in pool.map(get_api_key, init_tasks):
                    if res['status'] == 'success':
                        api_keys[res['host']] = res['api_key']
        except Exception as e:
            print(f"Worker Error during API key generation: {e}")
            conn.close()
            time.sleep(poll_interval)
            continue
        
        # ** NEW, ROBUST MODEL DISCOVERY LOGIC **
        # For any firewall that has an API key but no model, hostname, or sw_version, get the info.
        firewalls_to_update = [fw for fw in firewalls if fw['ip_address'] in api_keys and (not fw['model'] or not fw['hostname'] or not fw['sw_version'])]
        if firewalls_to_update:
            print(f"Found {len(firewalls_to_update)} firewalls with missing details. Discovering...")
            for fw in firewalls_to_update:
                try:
                    api_key = api_keys[fw['ip_address']]
                    sys_info_xml = requests.get(f"https://{fw['ip_address']}/api/?type=op&cmd=<show><system><info/></system></show>&key={api_key}", verify=False, timeout=10).content
                    root = ET.fromstring(sys_info_xml)
                    model = root.findtext('.//model')
                    hostname = root.findtext('.//hostname')
                    sw_version = root.findtext('.//sw-version')
                    if model and hostname and sw_version:
                        conn.execute('UPDATE firewalls SET model = ?, hostname = ?, sw_version = ? WHERE id = ?', (model, hostname, sw_version, fw['id']))
                        print(f"Discovered and saved model '{model}', hostname '{hostname}', and version '{sw_version}' for {fw['ip_address']}.")
                except Exception as e:
                    print(f"Could not discover model/hostname for {fw['ip_address']}: {e}")
            conn.commit()

        # ** CHANGE: Only fetch detailed specs for firewalls that are missing them. **
        details_query = "SELECT firewall_id FROM firewall_details"
        fws_with_details = {row['firewall_id'] for row in conn.execute(details_query).fetchall()}
        firewalls_needing_details = [fw for fw in firewalls if fw['ip_address'] in api_keys and fw['id'] not in fws_with_details]
        if firewalls_needing_details:
            print(f"Found {len(firewalls_needing_details)} firewalls missing detailed specs. Fetching...")
            with db_lock:
                for fw in firewalls_needing_details:
                    parse_and_store_fw_details(conn, fw['id'], api_keys[fw['ip_address']])
                conn.commit()
        
        # --- POLLING ---
        if not api_keys:
            print("Worker: Could not get API key for any firewalls. Check credentials in Settings. Waiting...")
            conn.close()
            time.sleep(poll_interval)
            continue
            
        poll_tasks = [(host, key, firewall_states.get(host, {})) for host, key in api_keys.items()]
        with multiprocessing.Pool(processes=len(poll_tasks)) as pool:
            results = pool.map(poll_single_firewall, poll_tasks)
        
        # --- SAVE RESULTS ---
        # Explicitly format the datetime object to a string to avoid DeprecationWarning in Python 3.12+
        timestamp_now_str = datetime.now().isoformat(sep=' ', timespec='microseconds')
        with db_lock:
            for res in results:
                host = res['host']
                firewall_id = next((fw['id'] for fw in firewalls if fw['ip_address'] == host), None)
                if not firewall_id: continue
                
                conn.execute('UPDATE firewalls SET last_checked = ?, status = ? WHERE id = ?', (timestamp_now_str, res['status'], firewall_id))
                if res['status'] == 'success':
                    firewall_states[host] = res['new_state']
                    s = res['data']
                    if s['total_input_bps'] > 0 or s['total_output_bps'] > 0 or s['active_sessions'] > 0:
                        conn.execute(
                            'INSERT INTO stats (firewall_id, timestamp, active_sessions, ssl_decrypt_sessions, total_input_bps, total_output_bps, cpu_load, dataplane_load, memory_utilization) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                            (firewall_id, timestamp_now_str, s['active_sessions'], s['ssl_decrypt_sessions'], s['total_input_bps'], s['total_output_bps'], s['cpu_load'], s['dataplane_load'], s['memory_utilization'])
                        )
            
            # --- NEW: Prune old statistics ---
            prune_query = f"DELETE FROM stats WHERE timestamp < datetime('now', '-{retention_days} days')"
            cursor = conn.execute(prune_query)
            if cursor.rowcount > 0: print(f"Pruned {cursor.rowcount} old stat records (older than {retention_days} days).")

            conn.commit()

        conn.close()
        if background_task_running.is_set():
            background_task_running.clear()
        print(f"Polling cycle finished. Sleeping for {poll_interval} seconds.")
        # Wait for the poll_interval, or until the manual_poll_event is set
        manual_poll_event.wait(timeout=poll_interval)
        manual_poll_event.clear() # Reset the event after waking up

def get_firewall_stats_for_timespan(conn, fw_id, timespan=None, start_date=None, end_date=None):
    """
    A centralized function to fetch and process firewall stats for a given timeframe.
    It can return raw or summarized data based on the timespan.
    """
    is_summarized = timespan in ['24h', '7d', '30d'] or (start_date and end_date and (datetime.strptime(end_date, '%Y-%m-%d') - datetime.strptime(start_date, '%Y-%m-%d')).days > 1)

    # Define query parameters based on the request
    if start_date and end_date:
        where_clause = "timestamp BETWEEN ? AND ?"
        query_params = (fw_id, f"{start_date} 00:00:00", f"{end_date} 23:59:59")
        if is_summarized:
            date_format_sql, date_format_py, title_prefix = '%Y-%m-%d', '%Y-%m-%d', "Daily Peak"
        else:
            title_prefix = "Raw Data"
    else:
        time_modifier_map = {'5m': '-5 minutes', '1h': '-1 hour', '6h': '-6 hours', '24h': '-24 hours', '7d': '-7 days', '30d': '-30 days'}
        time_modifier = time_modifier_map.get(timespan, '-5 minutes') # Default to 5 minutes for safety
        where_clause = "timestamp >= datetime('now', 'localtime', ?)"
        query_params = (fw_id, time_modifier)
        if is_summarized:
            if timespan == '24h':
                date_format_sql, date_format_py, title_prefix = '%Y-%m-%d %H:00', '%Y-%m-%d %H:%M', "Hourly Peak"
            else: # 7d, 30d
                date_format_sql, date_format_py, title_prefix = '%Y-%m-%d', '%Y-%m-%d', "Daily Peak"
        else:
            title_prefix = "Raw Data"

    # Select the correct query based on whether we need to summarize (MAX vs raw)
    if is_summarized:
        query = f"""
            SELECT strftime('{date_format_sql}', timestamp) as period,
                   MAX(active_sessions) as sessions, MAX(memory_utilization) as mem, MAX(total_input_bps) as input_bps,
                   MAX(total_output_bps) as output_bps, MAX(cpu_load) as cpu, MAX(dataplane_load) as dp, MAX(ssl_decrypt_sessions) as ssl_sessions
            FROM stats WHERE firewall_id = ? AND {where_clause}
            GROUP BY period ORDER BY period ASC;
        """
    else: # Raw data query
        query = f"""
            SELECT timestamp, active_sessions as sessions, memory_utilization as mem, total_input_bps as input_bps,
                   total_output_bps as output_bps, cpu_load as cpu, dataplane_load as dp, ssl_decrypt_sessions as ssl_sessions
            FROM stats WHERE firewall_id = ? AND {where_clause}
            ORDER BY timestamp ASC;
        """
    stats = conn.execute(query, query_params).fetchall()

    if not stats:
        return None # Return None if no data is found

    # Process data for charts
    if is_summarized:
        labels = [datetime.strptime(s['period'], date_format_py).strftime(date_format_py) for s in stats]
    else:
        labels = [datetime.strptime(s['timestamp'], '%Y-%m-%d %H:%M:%S.%f').strftime('%H:%M:%S') for s in stats]

    return {
        "labels": labels,
        "session_data": [s['sessions'] or 0 for s in stats],
        "ssl_session_data": [s['ssl_sessions'] or 0 for s in stats],
        "input_data_mbps": [(s['input_bps'] or 0) / 1000000 for s in stats],
        "output_data_mbps": [(s['output_bps'] or 0) / 1000000 for s in stats],
        "cpu_data": [s['cpu'] or 0 for s in stats],
        "mem_data": [s['mem'] or 0 for s in stats],
        "dataplane_data": [s['dp'] or 0 for s in stats],
        "title_prefix": title_prefix
    }


if __name__ == '__main__':
    # Add this for multiprocessing support in frozen executables (PyInstaller)
    import multiprocessing
    multiprocessing.freeze_support()

    load_key()
    init_db()
    worker_thread = threading.Thread(target=background_worker_loop, daemon=True)
    worker_thread.start()
    log = logging.getLogger('werkzeug')
    app.run(host='0.0.0.0', port=4000, debug=False)