import flask, io, csv
from flask import Response
import sqlite3
import os
import time
import requests
from datetime import datetime
import xml.etree.ElementTree as ET
from urllib3.exceptions import InsecureRequestWarning
import multiprocessing
import threading
from cryptography.fernet import Fernet
import report_generator
import logging
from pa_models import SPECS, SPECS_MAP

# --- Configuration ---
DB_FILE = "monitoring.db"
KEY_FILE = "secret.key"

# Suppress insecure request warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

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

# --- Database Functions ---
def get_db_connection():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('PRAGMA foreign_keys = ON;')
    conn.execute('''CREATE TABLE IF NOT EXISTS firewalls (id INTEGER PRIMARY KEY AUTOINCREMENT, ip_address TEXT UNIQUE NOT NULL, last_checked TIMESTAMP, status TEXT DEFAULT 'unknown');''')
    conn.execute('''CREATE TABLE IF NOT EXISTS stats (id INTEGER PRIMARY KEY AUTOINCREMENT, firewall_id INTEGER NOT NULL, timestamp TIMESTAMP NOT NULL, active_sessions INTEGER, total_input_bps REAL, total_output_bps REAL, cpu_load REAL, dataplane_load REAL, FOREIGN KEY (firewall_id) REFERENCES firewalls (id) ON DELETE CASCADE);''')
    conn.execute('''CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);''')
    conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('POLL_INTERVAL', '30')")
    
    # ** NEW: Add 'model' column to the firewalls table if it doesn't exist **
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(firewalls)")
    columns = [row['name'] for row in cursor.fetchall()]
    if 'model' not in columns:
        conn.execute("ALTER TABLE firewalls ADD COLUMN model TEXT;")
    if 'hostname' not in columns:
        conn.execute("ALTER TABLE firewalls ADD COLUMN hostname TEXT;")

    conn.commit()
    conn.close()

# --- Web Page Routes ---
@app.route('/')
def index():
    conn = get_db_connection()
    
    settings_row = conn.execute("SELECT value FROM settings WHERE key = 'POLL_INTERVAL'").fetchone()
    polling_interval = int(settings_row['value']) if settings_row else 30

    query = """
        SELECT f.id as firewall_id, f.ip_address, f.hostname, f.model, s.timestamp,
               COALESCE(s.active_sessions, 0) as active_sessions, 
               (COALESCE(s.total_input_bps, 0) / 1000000) as total_input_mbps, 
               (COALESCE(s.total_output_bps, 0) / 1000000) as total_output_mbps,
               COALESCE(s.cpu_load, 0) as cpu_load,
               COALESCE(s.dataplane_load, 0) as dataplane_load,
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
    
    # ** NEW: Process the results to add generation and format the timestamp **
    processed_stats = []
    for stat in stats_from_db:
        # Convert the database row to a mutable dictionary
        stat_dict = dict(stat)
        
        # Look up the generation based on the model
        model = stat_dict.get('model')
        stat_dict['generation'] = SPECS_MAP.get(model, {}).get('generation', 'N/A')
        
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
    selected_timespan = '7d'
    if flask.request.method == 'POST':
        selected_timespan = flask.request.form['timespan']
        time_modifier = {'7d': '-7 days', '30d': '-30 days'}.get(selected_timespan, '-7 days')
        
        conn = get_db_connection()
        firewalls = conn.execute('SELECT id, ip_address, model FROM firewalls').fetchall()
        
        results = []
        for fw in firewalls:
            res = {'ip_address': fw['ip_address'], 'model': fw['model']}
            
            query = f"SELECT MAX(active_sessions) as max_s, MAX(total_input_bps + total_output_bps) as max_tp FROM stats WHERE firewall_id = ? AND timestamp >= datetime('now', 'localtime', '{time_modifier}');"
            peak_stats = conn.execute(query, (fw['id'],)).fetchone()

            peak_sessions = peak_stats['max_s'] or 0
            peak_throughput_mbps = (peak_stats['max_tp'] or 0) / 1000000
            
            res['peak_sessions'] = peak_sessions
            res['peak_throughput'] = peak_throughput_mbps

            if fw['model'] and fw['model'] in SPECS_MAP:
                spec = SPECS_MAP[fw['model']]
                # ** NEW: Add generation to the results dictionary **
                res['generation'] = spec.get('generation', 'N/A')
                res['max_sessions'] = spec['max_sessions']
                res['max_throughput'] = spec['max_throughput_mbps']
                
                res['session_util'] = (peak_sessions / spec['max_sessions']) * 100 if spec['max_sessions'] > 0 else 0
                res['throughput_util'] = (peak_throughput_mbps / spec['max_throughput_mbps']) * 100 if spec['max_throughput_mbps'] > 0 else 0

                res['recommendation'] = 'Sized Appropriately'
                if res['session_util'] >= 80 or res['throughput_util'] >= 80:
                    current_generation = spec.get('generation')
                    same_gen_models = [s for s in SPECS if s.get('generation') == current_generation]
                    current_index = next((i for i, item in enumerate(same_gen_models) if item["model"] == fw['model']), -1)

                    if 0 <= current_index < len(same_gen_models) - 1:
                        res['recommendation'] = f"Upgrade to {same_gen_models[current_index + 1]['model']}"
                    else:
                        res['recommendation'] = "Upgrade Recommended (Highest in Series)"
            else:
                res.update({'generation': 'N/A', 'max_sessions': 'N/A', 'max_throughput': 'N/A', 'session_util': 0, 'throughput_util': 0, 'recommendation': 'Unknown Model'})
            
            results.append(res)
        conn.close()

    return flask.render_template('advisor.html', results=results, selected_timespan=selected_timespan)

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
        
        conn.commit()
        flask.flash("Settings saved successfully!")
        return flask.redirect(flask.url_for('settings'))

    # Display settings (unchanged)
    settings_data = {row['key']: row['value'] for row in conn.execute("SELECT key, value FROM settings").fetchall()}
    conn.close()
    return flask.render_template('settings.html', settings=settings_data)

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

@app.route('/export/pdf')
def export_pdf():
    print("Server-side PDF export process started...")
    timespan = flask.request.args.get('timespan', '1h')
    report_type = flask.request.args.get('type', 'graphs_only')
    try:
        pdf_data = report_generator.generate_report_pdf(DB_FILE, timespan, report_type)
        if pdf_data is None: return "No data available for the selected period.", 404
        print("PDF generation complete. Sending file to user.")
        download_name = f"panos-report_{timespan}_{report_type}_{datetime.now().strftime('%Y%m%d-%H%M%S')}.pdf"
        return Response(pdf_data, mimetype='application/pdf', headers={'Content-Disposition': f'attachment;filename={download_name}'})
    except Exception as e:
        print(f"An error occurred during PDF export: {e}")
        return f"An error occurred: {e}", 500

@app.route('/firewall/<int:fw_id>')
def firewall_detail(fw_id):
    timespan = flask.request.args.get('timespan', '1h')
    conn = get_db_connection()
    
    # Fetch all necessary firewall details, including the new hostname
    fw = conn.execute('SELECT ip_address, hostname, model FROM firewalls WHERE id = ?', (fw_id,)).fetchone()
    
    if not fw:
        conn.close()
        return "Firewall not found", 404

    # **FIX**: This logic looks up the generation based on the fetched model.
    model = fw['model']
    generation = SPECS_MAP.get(model, {}).get('generation', 'N/A')

    chart_data = get_firewall_stats_for_timespan(conn, fw_id, timespan)
    summary_stats = None
    if chart_data:
        time_modifier = {'1h': '-1 hour', '6h': '-6 hours', '24h': '-24 hours', '7d': '-7 days', '30d': '-30 days'}.get(timespan, '-5 minutes')
        query_summary = f"SELECT MAX(active_sessions) as max_sessions, MAX(total_input_bps) as max_input, MAX(total_output_bps) as max_output, MAX(cpu_load) as max_cpu, MAX(dataplane_load) as max_dp FROM stats WHERE firewall_id = ? AND timestamp >= datetime('now', 'localtime', '{time_modifier}');"
        summary_stats = conn.execute(query_summary, (fw_id,)).fetchone()
    full_data = {"chart_data": chart_data, "summary_data": dict(summary_stats) if summary_stats else None}
    conn.close()

    return flask.render_template(
        'firewall_detail.html',
        fw_id=fw_id,
        ip_address=fw['ip_address'],
        hostname=fw['hostname'],
        # **FIX**: Pass the corrected model and generation to the template
        model=model,
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

@app.route('/import_from_panorama', methods=['POST'])
def import_from_panorama():
    key = load_key()
    conn = get_db_connection()
    settings_rows = conn.execute("SELECT key, value FROM settings").fetchall()
    settings = {row['key']: row['value'] for row in settings_rows}
    conn.close()

    # Get Panorama config from the database
    pano_host = settings.get('PANORAMA_HOST')
    pano_user = settings.get('PANORAMA_USER')
    encrypted_pass = settings.get('PANORAMA_PASSWORD')

    if not all([pano_host, pano_user, encrypted_pass]):
        flask.flash("Panorama settings are incomplete. Please configure them on the Settings page.")
        return flask.redirect(flask.url_for('manage_firewalls'))

    pano_pass = decrypt_message(encrypted_pass, key)
    
    try:
        # 1. Get API Key from Panorama
        api_params = {'type': 'keygen', 'user': pano_user, 'password': pano_pass}
        response = requests.get(f"https://{pano_host}/api/", params=api_params, verify=False, timeout=10)
        response.raise_for_status()
        
        tree = ET.fromstring(response.content)
        api_key = tree.find('.//key')
        if api_key is None or not api_key.text:
            raise Exception("Failed to get API key from Panorama. Check credentials.")

        # 2. Get list of connected devices
        cmd = "<show><devices><connected></connected></devices></show>"
        response = requests.get(f"https://{pano_host}/api/?type=op&cmd={cmd}&key={api_key.text}", verify=False, timeout=20)
        response.raise_for_status()

        # 3. Parse XML and import IPs into the database
        device_tree = ET.fromstring(response.content)
        ips_to_import = [dev.findtext('ip-address') for dev in device_tree.findall('.//devices/entry')]
        
        imported_count = 0
        conn = get_db_connection()
        for ip in ips_to_import:
            if ip:
                try:
                    # INSERT OR IGNORE will skip duplicates
                    cursor = conn.execute('INSERT OR IGNORE INTO firewalls (ip_address) VALUES (?)', (ip,))
                    # The number of rows changed will be 1 for a new insert, 0 for an ignored duplicate
                    if cursor.rowcount > 0:
                        imported_count += 1
                except sqlite3.IntegrityError:
                    pass # Should be caught by IGNORE but here for safety
        conn.commit()
        conn.close()
        
        flask.flash(f"Import successful! Added {imported_count} new firewalls from Panorama. Duplicates were ignored.")

    except Exception as e:
        flask.flash(f"Error importing from Panorama: {e}")

    return flask.redirect(flask.url_for('manage_firewalls'))

@app.route('/delete_firewall/<int:fw_id>', methods=['POST'])
def delete_firewall(fw_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM firewalls WHERE id = ?', (fw_id,)); conn.commit()
    conn.close()
    return flask.redirect(flask.url_for('manage_firewalls'))

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

def poll_single_firewall(args):
    """Worker function to poll metrics from a single firewall."""
    host, api_key, previous_state = args
    try:
        # API Calls
        session_xml = requests.get(f"https://{host}/api/?type=op&key={api_key}&cmd=<show><session><info/></session></show>", verify=False, timeout=15).content
        if_counter_xml = requests.get(f"https://{host}/api/?type=op&key={api_key}&cmd=<show><counter><interface>all</interface></counter></show>", verify=False, timeout=15).content
        resource_xml = requests.get(f"https://{host}/api/?type=op&key={api_key}&cmd=<show><running><resource-monitor></resource-monitor></running></show>", verify=False, timeout=15).content
        
        # Process Session info
        session_tree = ET.fromstring(session_xml)
        active_sessions = int(session_tree.find('.//num-active').text or 0)
        
        # Process Resource monitor info
        resource_tree = ET.fromstring(resource_xml)
        cpu_load = 0.0
        dataplane_load = 0.0
        all_core_averages = []
        
        data_processors_node = resource_tree.find('.//data-processors')
        if data_processors_node is not None:
            for dp_node in data_processors_node:
                minute_node = dp_node.find('minute')
                if minute_node is not None:
                    cpu_avg_node = minute_node.find('cpu-load-average')
                    if cpu_avg_node is not None:
                        for core_entry in cpu_avg_node.findall('entry'):
                            value_str = core_entry.findtext('value')
                            if value_str:
                                second_loads = [int(v) for v in value_str.split(',') if v.isdigit()]
                                if second_loads:
                                    all_core_averages.append(sum(second_loads) / len(second_loads))
        
        if all_core_averages:
            # ** CHANGE: The raw values appear to be scaled by a factor of 10. **
            # We multiply by 10 here to get the true percentage.
            dataplane_load = (sum(all_core_averages) / len(all_core_averages)) * 10
            cpu_load = max(all_core_averages) * 10

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
                "total_input_bps": total_in_bps, 
                "total_output_bps": total_out_bps,
                "cpu_load": cpu_load,
                "dataplane_load": dataplane_load
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

        if not fw_user or not encrypted_pass:
            print("Worker: Credentials not set in database. Waiting...")
            conn.close()
            time.sleep(poll_interval)
            continue
            
        fw_password = decrypt_message(encrypted_pass, key)
        firewalls = conn.execute('SELECT id, ip_address, hostname, model FROM firewalls').fetchall()
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
        # For any firewall that has an API key but no model or hostname, get the info.
        firewalls_to_update = [fw for fw in firewalls if fw['ip_address'] in api_keys and (not fw['model'] or not fw['hostname'])]
        if firewalls_to_update:
            print(f"Found {len(firewalls_to_update)} firewalls with unknown models/hostnames. Discovering...")
            for fw in firewalls_to_update:
                try:
                    api_key = api_keys[fw['ip_address']]
                    sys_info_xml = requests.get(f"https://{fw['ip_address']}/api/?type=op&cmd=<show><system><info/></system></show>&key={api_key}", verify=False, timeout=10).content
                    root = ET.fromstring(sys_info_xml)
                    model = root.findtext('.//model')
                    hostname = root.findtext('.//hostname')
                    if model and hostname:
                        conn.execute('UPDATE firewalls SET model = ?, hostname = ? WHERE id = ?', (model, hostname, fw['id']))
                        print(f"Discovered and saved model '{model}' and hostname '{hostname}' for {fw['ip_address']}.")
                except Exception as e:
                    print(f"Could not discover model/hostname for {fw['ip_address']}: {e}")
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
        timestamp_now = datetime.now()
        for res in results:
            host = res['host']
            firewall_id = next((fw['id'] for fw in firewalls if fw['ip_address'] == host), None)
            if not firewall_id: continue
            
            conn.execute('UPDATE firewalls SET last_checked = ?, status = ? WHERE id = ?', (timestamp_now, res['status'], firewall_id))
            if res['status'] == 'success':
                firewall_states[host] = res['new_state']
                s = res['data']
                if s['total_input_bps'] > 0 or s['total_output_bps'] > 0 or s['active_sessions'] > 0:
                    conn.execute(
                        'INSERT INTO stats (firewall_id, timestamp, active_sessions, total_input_bps, total_output_bps, cpu_load, dataplane_load) VALUES (?, ?, ?, ?, ?, ?, ?)',
                        (firewall_id, timestamp_now, s['active_sessions'], s['total_input_bps'], s['total_output_bps'], s['cpu_load'], s['dataplane_load'])
                    )
        
        conn.commit()
        conn.close()
        print(f"Polling cycle finished. Sleeping for {poll_interval} seconds.")
        time.sleep(poll_interval)

def get_firewall_stats_for_timespan(conn, fw_id, timespan):
    """
    A centralized function to fetch and process firewall stats for a given timeframe.
    It can return raw or summarized data based on the timespan.
    """
    is_summarized = timespan in ['24h', '7d', '30d']
    
    # Define query parameters based on the chosen timespan. Use MAX for summarized views.
    if is_summarized:
        if timespan == '7d':
            time_modifier, date_format_sql, date_format_py, title_prefix = '-7 days', '%Y-%m-%d', '%Y-%m-%d', "Daily Peak"
        elif timespan == '30d':
            time_modifier, date_format_sql, date_format_py, title_prefix = '-30 days', '%Y-%m-%d', '%Y-%m-%d', "Daily Peak"
        else: # 24h
            time_modifier, date_format_sql, date_format_py, title_prefix = '-24 hours', '%Y-%m-%d %H:00', '%Y-%m-%d %H:%M', "Hourly Peak"
    else: # Raw data reports
        if timespan == '1h':
            time_modifier, title_prefix = '-1 hour', "Raw Data"
        elif timespan == '6h':
            time_modifier, title_prefix = '-6 hours', "Raw Data"
        else: # 5m
            time_modifier, title_prefix = '-5 minutes', "Raw Data"
    
    # Select the correct query based on whether we need to summarize (MAX vs raw)
    if is_summarized:
        query = f"""
            SELECT strftime('{date_format_sql}', timestamp) as period,
                   MAX(active_sessions) as sessions, MAX(total_input_bps) as input_bps,
                   MAX(total_output_bps) as output_bps, MAX(cpu_load) as cpu, MAX(dataplane_load) as dp
            -- **FIX**: Added 'localtime' to the time comparison
            FROM stats WHERE firewall_id = ? AND timestamp >= datetime('now', 'localtime', '{time_modifier}')
            GROUP BY period ORDER BY period ASC;
        """
    else: # Raw data query
        query = f"""
            SELECT timestamp, active_sessions as sessions, total_input_bps as input_bps,
                   total_output_bps as output_bps, cpu_load as cpu, dataplane_load as dp
            -- **FIX**: Added 'localtime' to the time comparison
            FROM stats WHERE firewall_id = ? AND timestamp >= datetime('now', 'localtime', '{time_modifier}')
            ORDER BY timestamp ASC;
        """
    
    stats = conn.execute(query, (fw_id,)).fetchall()

    if not stats:
        return None # Return None if no data is found

    # Process data for charts
    if is_summarized:
        labels = [datetime.strptime(s['period'], date_format_py).strftime(date_format_py) for s in stats]
    else:
        labels = [datetime.strptime(s['timestamp'], '%Y-%m-%d %H:%M:%S.%f').strftime('%H:%M:%S') for s in stats]

    return {
        "labels": labels,
        "session_data": [s['sessions'] for s in stats],
        "input_data_mbps": [s['input_bps'] / 1000000 for s in stats],
        "output_data_mbps": [s['output_bps'] / 1000000 for s in stats],
        "cpu_data": [s['cpu'] for s in stats],
        "dataplane_data": [s['dp'] for s in stats],
        "title_prefix": title_prefix
    }

if __name__ == '__main__':
    load_key()
    init_db()
    worker_thread = threading.Thread(target=background_worker_loop, daemon=True)
    worker_thread.start()
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)    
    app.run(host='0.0.0.0', port=4000, debug=False)