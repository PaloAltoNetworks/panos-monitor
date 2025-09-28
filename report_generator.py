import sqlite3
import io
import tempfile
from datetime import datetime
from fpdf import FPDF
import matplotlib
import matplotlib.pyplot as plt

# Use a backend that doesn't require a GUI
matplotlib.use('Agg')

# --- HELPER FUNCTIONS ---

def _get_stats_from_db(conn, fw_id, timespan):
    """
    A self-contained helper function to fetch and process firewall stats for a given timeframe.
    It lives inside this file and does not depend on any other module.
    """
    is_summarized = timespan in ['24h', '7d', '30d']
    
    if is_summarized:
        if timespan == '7d':
            time_modifier, date_format_sql, date_format_py, title_prefix = '-7 days', '%Y-%m-%d', '%Y-%m-%d', "Daily Average"
        elif timespan == '30d':
            time_modifier, date_format_sql, date_format_py, title_prefix = '-30 days', '%Y-%m-%d', '%Y-%m-%d', "Daily Average"
        else: # 24h
            time_modifier, date_format_sql, date_format_py, title_prefix = '-24 hours', '%Y-%m-%d %H:00', '%Y-%m-%d %H:%M', "Hourly Average"
    else: # Raw data reports
        if timespan == '1h':
            time_modifier, title_prefix = '-1 hour', "Raw Data"
        elif timespan == '6h':
            time_modifier, title_prefix = '-6 hours', "Raw Data"
        else: # 5m
            time_modifier, title_prefix = '-5 minutes', "Raw Data"
    
    if is_summarized:
        query = f"SELECT strftime('{date_format_sql}', timestamp) as period, AVG(active_sessions) as sessions, AVG(total_input_bps) as input_bps, AVG(total_output_bps) as output_bps, AVG(cpu_load) as cpu, AVG(dataplane_load) as dp FROM stats WHERE firewall_id = ? AND timestamp >= datetime('now', 'localtime', '{time_modifier}') GROUP BY period ORDER BY period ASC;"
    else: # Raw data query
        query = f"SELECT timestamp, active_sessions as sessions, total_input_bps as input_bps, total_output_bps as output_bps, cpu_load as cpu, dataplane_load as dp FROM stats WHERE firewall_id = ? AND timestamp >= datetime('now', 'localtime', '{time_modifier}') ORDER BY timestamp ASC;"
    
    stats_charts = conn.execute(query, (fw_id,)).fetchall()

    if not stats_charts:
        return None

    query_summary = f"SELECT MAX(active_sessions) as max_sessions, MAX(total_input_bps) as max_input, MAX(total_output_bps) as max_output, MAX(cpu_load) as max_cpu, MAX(dataplane_load) as max_dp FROM stats WHERE firewall_id = ? AND timestamp >= datetime('now', 'localtime', '{time_modifier}');"
    summary_stats = conn.execute(query_summary, (fw_id,)).fetchone()

    if is_summarized:
        labels = [datetime.strptime(s['period'], date_format_py).strftime(date_format_py) for s in stats_charts]
    else:
        labels = [datetime.strptime(s['timestamp'], '%Y-%m-%d %H:%M:%S.%f').strftime('%H:%M:%S') for s in stats_charts]

    return {
        "chart_data": {
            "labels": labels, "session_data": [s['sessions'] for s in stats_charts],
            "input_data_mbps": [s['input_bps'] / 1000000 for s in stats_charts],
            "output_data_mbps": [s['output_bps'] / 1000000 for s in stats_charts],
            "cpu_data": [s['cpu'] for s in stats_charts], "dataplane_data": [s['dp'] for s in stats_charts]
        },
        "summary_data": dict(summary_stats), "title_prefix": title_prefix
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

def create_summary_table_page(pdf, firewalls, conn, timespan, title):
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

    # Table Header
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(60, 8, 'Firewall IP', 1)
    pdf.cell(35, 8, 'Max Sessions', 1)
    pdf.cell(40, 8, 'Peak Input (Mbps)', 1)
    pdf.cell(40, 8, 'Peak Output (Mbps)', 1)
    pdf.cell(40, 8, 'Peak CPU Load (%)', 1)
    pdf.cell(40, 8, 'Peak DP Load (%)', 1)
    pdf.ln()

    # Table Body
    pdf.set_font("Helvetica", "", 9)
    for fw in firewalls:
        full_data = _get_stats_from_db(conn, fw['id'], timespan)
        if full_data and full_data['summary_data']:
            summary = full_data['summary_data']
            pdf.cell(60, 8, fw['ip_address'], 1)
            pdf.cell(35, 8, str(summary.get('max_sessions', 'N/A')), 1)
            pdf.cell(40, 8, f"{summary.get('max_input', 0) / 1000000:.2f}", 1)
            pdf.cell(40, 8, f"{summary.get('max_output', 0) / 1000000:.2f}", 1)
            pdf.cell(40, 8, f"{summary.get('max_cpu', 0):.2f}", 1)
            pdf.cell(40, 8, f"{summary.get('max_dp', 0):.2f}", 1)
            pdf.ln()

# --- MAIN PDF GENERATION FUNCTION ---

def generate_report_pdf(db_file, timespan, report_type='graphs_only'):
    conn = sqlite3.connect(db_file, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    firewalls = conn.execute('SELECT id, ip_address FROM firewalls ORDER BY ip_address').fetchall()

    if not firewalls:
        conn.close()
        return None

    pdf = FPDF(orientation="L", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    
    # --- Define Title and Query Parameters ---
    is_summarized = timespan in ['24h', '7d', '30d']
    if is_summarized:
        if timespan == '7d': title_prefix, time_modifier, date_format_sql, date_format_py = "Daily Peak", '-7 days', '%Y-%m-%d', '%Y-%m-%d'
        elif timespan == '30d': title_prefix, time_modifier, date_format_sql, date_format_py = "Daily Peak", '-30 days', '%Y-%m-%d', '%Y-%m-%d'
        else: # 24h
            title_prefix, time_modifier, date_format_sql, date_format_py = "Hourly Peak", '-24 hours', '%Y-%m-%d %H:00', '%Y-%m-%d %H:%M'
    else: # Raw data
        if timespan == '1h': title_prefix, time_modifier = "Raw Data", '-1 hour'
        elif timespan == '6h': title_prefix, time_modifier = "Raw Data", '-6 hours'
        else: # 5m
            # **FIX**: Corrected the variable assignment for the 5-minute case
            title_prefix = "Raw Data"
            time_modifier = '-5 minutes'
    
    report_title = f"{title_prefix} Report ({timespan})"

    # --- Create Title Page or Summary Page ---
    if report_type == 'combined':
        create_summary_table_page(pdf, firewalls, conn, timespan, report_title)
    elif report_type == 'table_only':
        create_summary_table_page(pdf, firewalls, conn, timespan, report_title)
    else: # graphs_only
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 24); pdf.cell(0, 50, "PAN-OS Performance Report", 0, 1, 'C')
        pdf.set_font("Helvetica", "", 16); pdf.cell(0, 10, report_title, 0, 1, 'C')
        pdf.set_font("Helvetica", "", 12); pdf.cell(0, 10, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1, 'C')
        
    # --- Create Graph Pages (if needed) ---
    if report_type in ['graphs_only', 'combined']:
        for fw in firewalls:
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 16)
            pdf.cell(0, 10, f"Graphs for {fw['ip_address']}", 0, 1, 'C')

            if is_summarized:
                query = f"SELECT strftime('{date_format_sql}', timestamp) as period, MAX(active_sessions) as sessions, MAX(total_input_bps) as input_bps, MAX(total_output_bps) as output_bps, MAX(cpu_load) as cpu, MAX(dataplane_load) as dp FROM stats WHERE firewall_id = ? AND timestamp >= datetime('now', 'localtime', '{time_modifier}') GROUP BY period ORDER BY period ASC;"
            else:
                query = f"SELECT timestamp, active_sessions as sessions, total_input_bps as input_bps, total_output_bps as output_bps, cpu_load as cpu, dataplane_load as dp FROM stats WHERE firewall_id = ? AND timestamp >= datetime('now', 'localtime', '{time_modifier}') ORDER BY timestamp ASC;"
            
            stats = conn.execute(query, (fw['id'],)).fetchall()
            
            if not stats:
                pdf.set_font("Helvetica", "", 12); pdf.cell(0, 10, "No data for this period.", 0, 1, 'L'); continue
                
            if is_summarized:
                labels = [datetime.strptime(s['period'], date_format_py).strftime(date_format_py) for s in stats]
            else:
                labels = [datetime.strptime(s['timestamp'], '%Y-%m-%d %H:%M:%S.%f').strftime('%H:%M:%S') for s in stats]
            
            chart_data = {"labels": labels, "session_data": [s['sessions'] for s in stats], "input_data_mbps": [s['input_bps'] / 1000000 for s in stats], "output_data_mbps": [s['output_bps'] / 1000000 for s in stats], "cpu_data": [s['cpu'] for s in stats], "dataplane_data": [s['dp'] for s in stats]}
            
            input_chart = create_chart_image(chart_data['labels'], [{'label': 'Input (Mbps)', 'data': chart_data['input_data_mbps'], 'color': 'blue'}], f"{title_prefix} Input Throughput", 'Mbps')
            output_chart = create_chart_image(chart_data['labels'], [{'label': 'Output (Mbps)', 'data': chart_data['output_data_mbps'], 'color': 'red'}], f"{title_prefix} Output Throughput", 'Mbps')
            session_chart = create_chart_image(chart_data['labels'], [{'label': 'Active Sessions', 'data': chart_data['session_data'], 'color': 'green'}], f"{title_prefix} Active Sessions", 'Sessions')
            load_chart = create_chart_image(chart_data['labels'], [{'label': 'CPU Load (%)', 'data': chart_data['cpu_data'], 'color': 'orange'}, {'label': 'DP Load (%)', 'data': chart_data['dataplane_data'], 'color': 'purple'}], f"{title_prefix} CPU & Dataplane Load", 'Load %')
            
            chart_width, chart_height, margin = 130, 70, 15
            pdf.image(input_chart, x=margin, y=30, w=chart_width, h=chart_height)
            pdf.image(output_chart, x=margin + chart_width + 10, y=30, w=chart_width, h=chart_height)
            pdf.image(session_chart, x=margin, y=30 + chart_height + 10, w=chart_width, h=chart_height)
            pdf.image(load_chart, x=margin + chart_width + 10, y=30 + chart_height + 10, w=chart_width, h=chart_height)

    conn.close()
    return bytes(pdf.output())