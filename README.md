# PAN-OS Stats Monitor

A simple, web-based monitoring dashboard for Palo Alto Networks firewalls. This tool polls devices for session count and throughput, stores the data in a local SQLite database, and provides a web interface to view historical performance graphs and export reports.





---
## Features ✨

* **Web-Based Dashboard:** A clean, centralized dashboard to view the latest status for all monitored firewalls, including their **model**, status, CPU/DP load, and aggregate throughput.
* **Historical Graphing:** Click on any firewall to view detailed historical graphs for its key performance metrics.
* **Selectable Timeframes:** View graphs and summary data for various timeframes, from the last 5 minutes to the last 30 days.
* **Upgrade Advisor:** Analyzes peak usage against known model specifications and recommends a hardware upgrade if utilization exceeds an 80% threshold.
* **Peak Statistics Summary:** View a table of peak values (max sessions, highest throughput, max CPU/DP load) for each firewall over your selected timeframe.
* **Flexible Exporting:** Export peak statistics to CSV, or generate PDF reports in multiple formats: Graphs Only, Table Only, or a Combined report.
* **CPU & Dataplane Monitoring:** Tracks the load average for both the management plane (peak core) and data plane (average of all cores).
* **Panorama Integration:** Import all connected firewalls directly from your Panorama instance with a single click.
* **Multi-Firewall Support:** Monitor dozens of firewalls. Firewalls can be added individually or bulk-imported from a text file.
* **Persistent Storage:** Uses a local SQLite database (`monitoring.db`) to store all configuration and historical statistics.
* **Web-Based Configuration:** Easily configure API credentials and the polling interval from a dedicated Settings page in the web UI.
* **Background Polling:** A multi-process background worker continuously polls devices without blocking the web interface.
* **Server-Side PDF Reporting:** Export multi-page PDF reports with summarized or raw data for various timeframes.

---
## Installation & Setup

Follow these steps to get the PAN-OS Stats Monitor running.

### 1. Prerequisites

Before you begin, you must have an administrator account on your devices with API access enabled.

* On your **firewalls**, navigate to **Device > Admin Roles**. Select a role, and in the **XML API** tab, ensure that **Report**, **Operational Requests**, and **Show** (under XML API) are checked. Assign this role to the user account you will use for polling.
* If using the Panorama import feature, the same API access must be enabled for your **Panorama** user account.

### 2. Clone the Repository

Clone the repository to your local machine:
```
git clone https://github.com/PaloAltoNetworks/panos-monitor
cd panos-monitor
```
### 3. Create a Python Virtual Environment

It's highly recommended to use a virtual environment to manage project dependencies.

* **Create the environment:**
    ```
    python3 -m venv panos-monitor
    ```
* **Activate the environment:**
    * On macOS or Linux:

        ```
        source panos-monitor/bin/activate
        ```
    * On Windows:

        ```
        panos-monitor\Scripts\activate
        ```
### 4. Install Dependencies

Install the required Python libraries from the `requirements.txt` file.
```
pip install -r requirements.txt
```
### 5. Customize Model Specifications

The application includes a `pa_models.py` file with specifications for a sample set of firewall models. For the Upgrade Advisor to be accurate, you should edit this file to include the models and correct performance specifications relevant to your environment.

### 6. (Optional) Add a Favicon

To add a custom icon to your browser tabs:
1. Create a `static` folder in your main project directory.
2. Place an icon file named `favicon.ico` inside the `static` folder.

---
## Usage Guide 🚀

### 1. Run the Application

Launch the Flask web server by running `app.py`:
```
python3 app.py
```
On the first run, the application will automatically create a `monitoring.db` database file and a `secret.key` encryption key file in the project directory.

### 2. Initial Configuration

1.  Open your web browser and navigate to `http://127.0.0.1:5000`.
2.  Navigate to the **Settings** page using the link in the navigation bar.
3.  Fill in the **Firewall Polling Settings**. These are the credentials the poller will use to connect to individual firewalls.
4.  Fill in the **Panorama Import Settings**. These are the credentials for your Panorama instance, used only for importing devices.
5.  Set the **Polling Interval** and click **Save Settings**.

The background worker will automatically pick up these settings and begin polling.

### 3. Adding Firewalls

Navigate to the **Manage Firewalls** page. You have three options:
1.  **Import from Panorama:** Click the button to automatically discover and import all connected firewalls from your configured Panorama instance. Duplicates will be ignored.
2.  **Add Single Firewall:** Enter an IP address manually.
3.  **Import from File:** Upload a `.txt` file with one IP address per line.

The background poller will automatically detect the model of newly added firewalls on its next cycle.

### 4. Viewing Data and Graphs

* The **Dashboard** shows the latest statistics for all devices.
* Click on any firewall's **IP address** to navigate to its detail page. Here you can view a summary table of peak statistics, see historical graphs, and use the timeframe selector to switch between views.

### 5. Using the Upgrade Advisor

* Navigate to the **Upgrade Advisor** page from the main menu.
* Select an analysis timeframe (e.g., Last 30 Days) and click 'Analyze'.
* The page will display a table showing the peak usage for each firewall compared to its model's capacity and provide a recommendation (e.g., 'Sized Appropriately' or 'Upgrade Recommended').

### 6. Exporting Data

* **CSV:** On any firewall's detail page, export the summary table to a CSV file by clicking the **'Export Table to CSV'** button.
* **PDF:** Navigate to the **Manage Firewalls** page and use the **Export PDF Report** dropdown. You can choose from three report types (Table Only, Graphs Only, Combined) across multiple timeframes.

---
## How It Works

* **Front-End:** A **Flask** web application serves the HTML pages.
* **Back-End:** A **background thread** runs a continuous polling loop, which uses a **multiprocessing pool** to poll devices concurrently.
* **Data Storage:** A single-file **SQLite** database (`monitoring.db`) stores all application data.
* **Configuration:** Application settings, including encrypted API credentials, are stored in the `settings` table. Hardware specifications for the Upgrade Advisor are stored in the `pa_models.py` file.
* **Security:** The password encryption key is stored in the `secret.key` file. **Important:** Do not delete this file, as it is required to decrypt the stored credentials. If you back up the database, back up this key file as well.
* **PDF Generation:** PDF reports are generated entirely on the server using **Matplotlib** to create chart images and **FPDF2** to assemble the document.
