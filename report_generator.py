import sqlite3
import io
import tempfile
from datetime import datetime
import matplotlib
from fpdf import FPDF
import matplotlib.pyplot as plt # Keep this import

# Use a backend that doesn't require a GUI
matplotlib.use('Agg')

# --- NEW: Remove import from pa_models.py ---
# from pa_models import SPECS_MAP


# --- HELPER FUNCTIONS ---

def load_specs_from_db(conn):
    """Loads all model specifications from the database into a dictionary."""
    models = conn.execute("SELECT * FROM firewall_models").fetchall()
    return {m['model']: dict(m) for m in models}

def _fetch_and_process_data(conn, fw_id, timespan):
    """
    A centralized helper function to fetch and process firewall stats for a given timeframe.
    This function consistently uses MAX() for summarized reports to show peak values.
    """
    is_summarized = timespan in ['24h', '7d', '30d']
    
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
    
    if is_summarized:
        query = f"SELECT strftime('{date_format_sql}', timestamp) as period, MAX(active_sessions) as sessions, MAX(total_input_bps) as input_bps, MAX(total_output_bps) as output_bps, MAX(cpu_load) as cpu, MAX(dataplane_load) as dp FROM stats WHERE firewall_id = ? AND timestamp >= datetime('now', 'localtime', '{time_modifier}') GROUP BY period ORDER BY period ASC;"
    else: # Raw data query
        query = f"SELECT timestamp, active_sessions as sessions, total_input_bps as input_bps, total_output_bps as output_bps, cpu_load as cpu, dataplane_load as dp FROM stats WHERE firewall_id = ? AND timestamp >= datetime('now', 'localtime', '{time_modifier}') ORDER BY timestamp ASC;"
    
    stats_charts = conn.execute(query, (fw_id,)).fetchall()

    if not stats_charts:
        return None

    if is_summarized:
        labels = [datetime.strptime(s['period'], date_format_py).strftime(date_format_py) for s in stats_charts]
    else:
        labels = [datetime.strptime(s['timestamp'], '%Y-%m-%d %H:%M:%S.%f').strftime('%H:%M:%S') for s in stats_charts]

    return {
        "labels": labels,
        "session_data": [s['sessions'] for s in stats_charts],
        "input_data_mbps": [s['input_bps'] / 1000000 for s in stats_charts],
        "output_data_mbps": [s['output_bps'] / 1000000 for s in stats_charts],
        "cpu_data": [s['cpu'] for s in stats_charts],
        "dataplane_data": [s['dp'] for s in stats_charts],
        "title_prefix": title_prefix
    }

def create_chart_image(labels, datasets, title, y_label):
    fig, ax = plt.subplots(figsize=(10, 4))
    for ds in datasets:
        marker_style = 'o' if 'Raw' in title else ''
        fill_style = True if len(datasets) == 1 else False
        ax.plot(labels, ds['data'], label=ds['label'], color=ds['color'], marker=marker_style, markersize=2, linestyle='-')
        if fill_style: ax.fill_between(labels, ds['data'], color=ds['color'], alpha=0.1)
    ax.set_title(title)
    ax.set_ylabel(y_label)
    ax.grid(True, which='both', linestyle='--', linewidth=0.5)
    if len(labels) > 20: ax.xaxis.set_major_locator(plt.MaxNLocator(20))
    plt.xticks(rotation=45, ha="right", fontsize=8)
    plt.tight_layout()
    if len(datasets) > 1: ax.legend()
    buf = io.BytesIO()
    fig.savefig(buf, format='png', dpi=100)
    buf.seek(0)
    plt.close(fig)
    return buf

def create_summary_table_page(pdf, firewalls, conn, timespan, title, specs_map):
    """Generates the first page of the report with a summary table."""
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 24)
    pdf.cell(0, 50, "PAN-OS Performance Report", 0, 1, 'C')
    pdf.set_font("Helvetica", "", 16)
    pdf.cell(0, 10, title, 0, 1, 'C')
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 10, "Peak Statistics Summary", 0, 1, 'C')
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 10, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1, 'C')
    pdf.ln(5)

    time_modifier = {'1h': '-1 hour', '6h': '-6 hours', '24h': '-24 hours', '7d': '-7 days', '30d': '-30 days'}.get(timespan, '-5 minutes')
    
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(40, 8, 'Hostname', 1)
    pdf.cell(35, 8, 'Firewall IP', 1)
    pdf.cell(30, 8, 'Model', 1)
    pdf.cell(30, 8, 'Generation', 1)
    pdf.cell(35, 8, 'Max Sessions', 1)
    pdf.cell(35, 8, 'Peak Input (Mbps)', 1)
    pdf.cell(35, 8, 'Peak Output (Mbps)', 1)
    pdf.cell(25, 8, 'Peak CPU (%)', 1)
    pdf.cell(25, 8, 'Peak DP (%)', 1)
    pdf.ln()

    pdf.set_font("Helvetica", "", 9)
    for fw in firewalls:
        query = f"SELECT MAX(active_sessions) as max_sessions, MAX(total_input_bps) as max_input, MAX(total_output_bps) as max_output, MAX(cpu_load) as max_cpu, MAX(dataplane_load) as max_dp FROM stats WHERE firewall_id = ? AND timestamp >= datetime('now', 'localtime', '{time_modifier}');"
        summary = conn.execute(query, (fw['id'],)).fetchone()
        
        # **CHANGE**: Now uses the 'specs_map' variable that was passed in
        generation = specs_map.get(fw['model'], {}).get('generation', 'N/A') # Use .get() for safety

        if summary and summary['max_sessions'] is not None:
            pdf.cell(40, 8, fw['hostname'] or 'N/A', 1)
            pdf.cell(35, 8, fw['ip_address'], 1)
            pdf.cell(30, 8, fw['model'] or 'Unknown', 1)
            pdf.cell(30, 8, generation, 1)
            pdf.cell(35, 8, str(summary['max_sessions']), 1)
            pdf.cell(35, 8, f"{summary['max_input'] / 1000000:.2f}", 1)
            pdf.cell(35, 8, f"{summary['max_output'] / 1000000:.2f}", 1)
            pdf.cell(25, 8, f"{summary['max_cpu']:.2f}", 1)
            pdf.cell(25, 8, f"{summary['max_dp']:.2f}", 1)
            pdf.ln()

# --- MAIN PDF GENERATION FUNCTION ---

def generate_report_pdf(db_file, timespan, report_type='graphs_only'):
    conn = sqlite3.connect(db_file, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    firewalls = conn.execute('SELECT id, ip_address, hostname, model FROM firewalls ORDER BY ip_address').fetchall()

    if not firewalls:
        conn.close()
        return None
    
    specs_map = load_specs_from_db(conn) # Load specs from DB here

    pdf = FPDF(orientation="L", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    
    # --- This logic is now self-contained and correct ---
    # The title prefix is determined by the data fetching function.
    # We just need a default for the main title.
    title_prefix = "Peak" if timespan in ['24h', '7d', '30d'] else "Raw Data"
    report_title = f"{title_prefix} Report ({timespan})"

    # Handle the three different report types
    if report_type == 'table_only':
        create_summary_table_page(pdf, firewalls, conn, timespan, report_title, specs_map)
    
    elif report_type == 'combined':
        create_summary_table_page(pdf, firewalls, conn, timespan, report_title, specs_map)
        for fw in firewalls:
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 16)
            fw_name = fw['hostname'] or fw['ip_address']
            pdf.cell(0, 10, f"Graphs for {fw_name} ({fw['ip_address']})", 0, 1, 'C')
            model = fw['model'] or "Unknown"
            generation = specs_map.get(model, {}).get('generation', 'N/A')
            pdf.set_font("Helvetica", "", 12)
            pdf.cell(0, 10, f"Model: {model} | Generation: {generation}", 0, 1, 'C')
            
            chart_data = _fetch_and_process_data(conn, fw['id'], timespan)
            if not chart_data:
                pdf.set_font("Helvetica", "", 12)
                pdf.cell(0, 10, "No data for this period.", 0, 1, 'L')
                continue

            title_prefix = chart_data['title_prefix']
            input_chart = create_chart_image(chart_data['labels'], [{'label': 'Input (Mbps)', 'data': chart_data['input_data_mbps'], 'color': 'blue'}], f"{title_prefix} Input Throughput", 'Mbps')
            output_chart = create_chart_image(chart_data['labels'], [{'label': 'Output (Mbps)', 'data': chart_data['output_data_mbps'], 'color': 'red'}], f"{title_prefix} Output Throughput", 'Mbps')
            session_chart = create_chart_image(chart_data['labels'], [{'label': 'Active Sessions', 'data': chart_data['session_data'], 'color': 'green'}], f"{title_prefix} Active Sessions", 'Sessions')
            load_chart = create_chart_image(chart_data['labels'], [{'label': 'CPU Load (%)', 'data': chart_data['cpu_data'], 'color': 'orange'}, {'label': 'DP Load (%)', 'data': chart_data['dataplane_data'], 'color': 'purple'}], f"{title_prefix} CPU & Dataplane Load", 'Load %')
            chart_width, chart_height, margin = 130, 70, 15
            pdf.image(input_chart, x=margin, y=40, w=chart_width, h=chart_height)
            pdf.image(output_chart, x=margin + chart_width + 10, y=40, w=chart_width, h=chart_height)
            pdf.image(session_chart, x=margin, y=40 + chart_height + 10, w=chart_width, h=chart_height)
            pdf.image(load_chart, x=margin + chart_width + 10, y=40 + chart_height + 10, w=chart_width, h=chart_height)

    else: # This is the default 'graphs_only' report
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 24); pdf.cell(0, 50, "PAN-OS Performance Report", 0, 1, 'C')
        pdf.set_font("Helvetica", "", 16); pdf.cell(0, 10, report_title, 0, 1, 'C')
        pdf.set_font("Helvetica", "", 12); pdf.cell(0, 10, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1, 'C')
        
        for fw in firewalls:
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 16)
            fw_name = fw['hostname'] or fw['ip_address']
            pdf.cell(0, 10, f"Graphs for {fw_name} ({fw['ip_address']})", 0, 1, 'C')
            model = fw['model'] or "Unknown"
            generation = specs_map.get(model, {}).get('generation', 'N/A')
            pdf.set_font("Helvetica", "", 12)
            pdf.cell(0, 10, f"Model: {model} | Generation: {generation}", 0, 1, 'C')
            
            chart_data = _fetch_and_process_data(conn, fw['id'], timespan)
            if not chart_data:
                pdf.set_font("Helvetica", "", 12); pdf.cell(0, 10, "No data for this period.", 0, 1, 'L'); continue

            title_prefix = chart_data['title_prefix']
            input_chart = create_chart_image(chart_data['labels'], [{'label': 'Input (Mbps)', 'data': chart_data['input_data_mbps'], 'color': 'blue'}], f"{title_prefix} Input Throughput", 'Mbps')
            output_chart = create_chart_image(chart_data['labels'], [{'label': 'Output (Mbps)', 'data': chart_data['output_data_mbps'], 'color': 'red'}], f"{title_prefix} Output Throughput", 'Mbps')
            session_chart = create_chart_image(chart_data['labels'], [{'label': 'Active Sessions', 'data': chart_data['session_data'], 'color': 'green'}], f"{title_prefix} Active Sessions", 'Sessions')
            load_chart = create_chart_image(chart_data['labels'], [{'label': 'CPU Load (%)', 'data': chart_data['cpu_data'], 'color': 'orange'}, {'label': 'DP Load (%)', 'data': chart_data['dataplane_data'], 'color': 'purple'}], f"{title_prefix} CPU & Dataplane Load", 'Load %')
            chart_width, chart_height, margin = 130, 70, 15
            pdf.image(input_chart, x=margin, y=40, w=chart_width, h=chart_height)
            pdf.image(output_chart, x=margin + chart_width + 10, y=40, w=chart_width, h=chart_height)
            pdf.image(session_chart, x=margin, y=40 + chart_height + 10, w=chart_width, h=chart_height)
            pdf.image(load_chart, x=margin + chart_width + 10, y=40 + chart_height + 10, w=chart_width, h=chart_height)

    conn.close()
    return bytes(pdf.output())