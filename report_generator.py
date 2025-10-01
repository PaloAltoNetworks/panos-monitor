import sqlite3
import io
import tempfile
from datetime import datetime
import matplotlib
from fpdf import FPDF
import matplotlib.pyplot as plt # Keep this import

# Use a backend that doesn't require a GUI
matplotlib.use('Agg')

# --- NEW: Import the centralized data fetching function from app.py ---
from app import get_firewall_stats_for_timespan as _fetch_and_process_data

# --- NEW: Remove import from pa_models.py ---
# from pa_models import SPECS_MAP


# --- HELPER FUNCTIONS ---

def load_specs_from_db(conn):
    """Loads all model specifications from the database into a dictionary."""
    models = conn.execute("SELECT * FROM firewall_models").fetchall()
    return {m['model']: dict(m) for m in models}

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
    
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(40, 8, 'Hostname', 1, 0, 'C')
    pdf.cell(30, 8, 'Firewall IP', 1, 0, 'C')
    pdf.cell(25, 8, 'Model', 1, 0, 'C')
    pdf.cell(25, 8, 'Generation', 1, 0, 'C')
    pdf.cell(30, 8, 'Max Sessions', 1, 0, 'C')
    pdf.cell(30, 8, 'Peak Input (Mbps)', 1, 0, 'C')
    pdf.cell(30, 8, 'Peak Output (Mbps)', 1, 0, 'C')
    pdf.cell(25, 8, 'Peak CPU (%)', 1, 0, 'C')
    pdf.cell(25, 8, 'Peak DP (%)', 1, 0, 'C')
    pdf.ln()

    pdf.set_font("Helvetica", "", 8)
    for fw in firewalls:
        query = f"SELECT MAX(active_sessions) as max_sessions, MAX(total_input_bps) as max_input, MAX(total_output_bps) as max_output, MAX(cpu_load) as max_cpu, MAX(dataplane_load) as max_dp FROM stats WHERE firewall_id = ? AND timestamp >= datetime('now', 'localtime', '{time_modifier}');"
        summary = conn.execute(query, (fw['id'],)).fetchone()
        
        # **CHANGE**: Now uses the 'specs_map' variable that was passed in
        generation = specs_map.get(fw['model'], {}).get('generation', 'N/A') # Use .get() for safety

        if summary and summary['max_sessions'] is not None:
            pdf.cell(40, 8, fw['hostname'] or 'N/A', 1, 0, 'L')
            pdf.cell(30, 8, fw['ip_address'], 1, 0, 'L')
            pdf.cell(25, 8, fw['model'] or 'Unknown', 1, 0, 'L')
            pdf.cell(25, 8, generation, 1, 0, 'L')
            pdf.cell(30, 8, str(summary['max_sessions']), 1, 0, 'R')
            pdf.cell(30, 8, f"{summary['max_input'] / 1000000:.2f}", 1, 0, 'R')
            pdf.cell(30, 8, f"{summary['max_output'] / 1000000:.2f}", 1, 0, 'R')
            pdf.cell(25, 8, f"{summary['max_cpu']:.2f}", 1, 0, 'R')
            pdf.cell(25, 8, f"{summary['max_dp']:.2f}", 1, 0, 'R')
            pdf.ln()

def create_capacity_report_page(pdf, firewalls, conn):
    """Generates pages for the capacity report."""
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 24)
    pdf.cell(0, 50, "PAN-OS Capacity Report", 0, 1, 'C')
    pdf.set_font("Helvetica", "", 12)
    pdf.cell(0, 10, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1, 'C')
    pdf.ln(5)

    query = """
        SELECT
            f.id, f.hostname, f.ip_address, f.model, f.sw_version,
            d.max_rules, d.max_nat_rules, d.max_address_objects, d.max_service_objects, d.max_ipsec_tunnels, d.max_routes, d.max_mroutes, d.max_arp_entries, d.max_bfd_sessions, d.max_dns_cache, d.max_registered_ips,
            u.current_rules, u.current_nat_rules, u.current_address_objects, u.current_service_objects, u.current_ipsec_tunnels, u.last_updated, u.current_routes, u.current_registered_ips,
            u.current_mroutes, u.current_arp_entries, u.current_bfd_sessions, u.current_dns_cache
        FROM firewalls f
        LEFT JOIN firewall_details d ON f.id = d.firewall_id
        LEFT JOIN firewall_current_usage u ON f.id = u.firewall_id
        WHERE f.id = ?
    """

    for fw in firewalls:
        fw_data = conn.execute(query, (fw['id'],)).fetchone()
        if not fw_data: continue

        if not pdf.get_y() < pdf.h - 40: pdf.add_page() # Add a page break if not enough space

        pdf.set_font("Helvetica", "B", 14)
        fw_name = fw_data['hostname'] or fw_data['ip_address']
        pdf.cell(0, 10, f"Device: {fw_name} ({fw_data['ip_address']})", 0, 1, 'L')
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 5, f"Model: {fw_data['model'] or 'N/A'} | PAN-OS: {fw_data['sw_version'] or 'N/A'}", 0, 1, 'L')
        pdf.cell(0, 5, f"Last Usage Data: {fw_data['last_updated'] or 'Never'}", 0, 1, 'L')
        pdf.ln(5)

        if fw_data['current_rules'] is None:
            pdf.cell(0, 8, "No capacity usage data has been collected for this firewall.", 0, 1, 'L')
            pdf.ln(10)
            continue

        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(70, 8, 'Metric', 1, 0, 'C')
        pdf.cell(40, 8, 'Current Usage', 1, 0, 'C')
        pdf.cell(40, 8, 'Max Capacity', 1, 0, 'C')
        pdf.cell(40, 8, 'Utilization', 1, 1, 'C')

        pdf.set_font("Helvetica", "", 8)
        metrics = [
            ('Security Rules', 'current_rules', 'max_rules'), ('NAT Rules', 'current_nat_rules', 'max_nat_rules'),
            ('Address Objects', 'current_address_objects', 'max_address_objects'), ('Service Objects', 'current_service_objects', 'max_service_objects'),
            ('IPsec Tunnels', 'current_ipsec_tunnels', 'max_ipsec_tunnels'), ('Routes', 'current_routes', 'max_routes'),
            ('Multicast Routes', 'current_mroutes', 'max_mroutes'), ('ARP Entries', 'current_arp_entries', 'max_arp_entries'),
            ('BFD Sessions', 'current_bfd_sessions', 'max_bfd_sessions'), ('DNS Cache Entries', 'current_dns_cache', 'max_dns_cache'),
            ('Registered IPs (User-ID)', 'current_registered_ips', 'max_registered_ips')
        ]
        for label, current_key, max_key in metrics:
            current_val = fw_data[current_key] if fw_data[current_key] is not None else 'N/A'
            max_val = fw_data[max_key] if fw_data[max_key] is not None else 'N/A'
            util = (current_val / max_val * 100) if isinstance(current_val, int) and isinstance(max_val, int) and max_val > 0 else 0
            pdf.cell(70, 8, label, 1, 0, 'L')
            pdf.cell(40, 8, str(current_val) if isinstance(current_val, str) else f"{current_val:,}", 1, 0, 'R')
            pdf.cell(40, 8, str(max_val) if isinstance(max_val, str) else f"{max_val:,}", 1, 0, 'R')
            pdf.cell(40, 8, f"{util:.1f}%", 1, 1, 'R')
        pdf.ln(10)

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

    elif report_type == 'capacity':
        # This is a new, non-timespan based report
        create_capacity_report_page(pdf, firewalls, conn)
    
    elif report_type == 'combined':
        create_summary_table_page(pdf, firewalls, conn, timespan, report_title, specs_map)
        
        # Add a capacity page for each firewall before the graphs page
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, "Device Capacity Details", 0, 1, 'C')
        pdf.ln(5)
        # We can reuse the capacity report function, but it will add a new page for each firewall.
        # To make it flow better, we'll call it here. It will create a new page internally.
        # The create_capacity_report_page function is designed to loop, but we will call it inside our loop.
        # Let's call a modified version of it.
        # For simplicity, let's just add the capacity page for each firewall here.
        create_capacity_report_page(pdf, firewalls, conn)

        # Now add the graph pages
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