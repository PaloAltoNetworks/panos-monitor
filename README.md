# PAN-OS Stats Monitor

A simple, web-based monitoring dashboard for Palo Alto Networks firewalls. This tool polls devices for session count and throughput, stores the data in a local SQLite database, and provides a web interface to view historical performance graphs and export reports.



---
## Features ✨

* **Web-Based Dashboard:** A clean, centralized dashboard to view the latest status and aggregate throughput for all monitored firewalls.
* **Historical Graphing:** Click on any firewall to view detailed historical graphs of its session count and throughput over time.
* **Panorama Integration:** Import all connected firewalls directly from your Panorama instance with a single click.
* **Multi-Firewall Support:** Monitor dozens of firewalls. Firewalls can be added individually or bulk-imported from a text file.
* **Persistent Storage:** Uses a local SQLite database (`monitoring.db`) to store all configuration and historical statistics.
* **Web-Based Configuration:** Easily configure API credentials and the polling interval from a dedicated Settings page in the web UI.
* **Background Polling:** A multi-process background worker continuously polls devices without blocking the web interface.
* **Server-Side PDF Reporting:** Export a multi-page PDF report containing the graphs for all monitored firewalls.

---
## Installation & Setup

Follow these steps to get the PAN-OS Stats Monitor running.

### 1. Prerequisites

Before you begin, you must have an administrator account on your devices with API access enabled.

* On your **firewalls**, navigate to **Device > Admin Roles**. Select a role, and in the **XML API** tab, ensure that **Report** and **Operational Requests** are checked. Assign this role to the user account you will use for polling.
* If using the Panorama import feature, the same API access must be enabled for your **Panorama** user account.

### 2. Clone the Repository

Clone the repository to your local machine:
```
git clone <your-repository-url>
cd <your-repository-folder>
```

### 3. Create a Python Virtual Environment

It's highly recommended to use a virtual environment to manage project dependencies.

* **Create the environment:**
    ```
    python3 -m venv venv
    ```
* **Activate the environment:**
    * On macOS or Linux:
        ```
        source venv/bin/activate
        ```
    * On Windows:
        ```
        venv\Scripts\activate
        ```

### 4. Install Dependencies

Install the required Python libraries from the `requirements.txt` file.
```
pip install -r requirements.txt
```

---
## Usage Guide 🚀

### 1. Run the Application

Launch the Flask web server by running `app.py`:
```
python app.py
```
On the first run, the application will automatically create a `monitoring.db` database file and a `secret.key` encryption key file in the project directory.

### 2. Initial Configuration

1.  Open your web browser and navigate to `http://127.0.0.1:5000`.
2.  Navigate to the **Settings** page using the link in the navigation bar.
3.  Fill in the **Firewall Polling Settings**. These are the credentials the poller will use to connect to individual firewalls.
4.  Fill in the **Panorama Import Settings**. These are the credentials for your Panorama instance, used only for importing devices.
5.  Set the **Polling Interval** and click **Save Settings**.

The background worker will automatically pick up these settings and begin polling on its next cycle.

### 3. Adding Firewalls

Navigate to the **Manage Firewalls** page. You have three options:
1.  **Import from Panorama:** Click the button to automatically discover and import all connected firewalls from your configured Panorama instance. Duplicates will be ignored.
2.  **Add Single Firewall:** Enter an IP address manually.
3.  **Import from File:** Upload a `.txt` file with one IP address per line.

### 4. Viewing Data and Graphs

* The **Dashboard** will automatically update at the interval you specified in Settings, showing the latest statistics for all devices.
* Click on any firewall's **IP address** to navigate to its detail page, where you'll find historical graphs.

### 5. Exporting to PDF

* Click the **Export to PDF** button in the navigation bar at any time.
* The server will generate a multi-page PDF report and send it to your browser for download.

---
## How It Works

* **Front-End:** A **Flask** web application serves the HTML pages.
* **Back-End:** A **background thread** runs a continuous polling loop, which uses a **multiprocessing pool** to poll all devices concurrently.
* **Data Storage:** A single-file **SQLite** database (`monitoring.db`) stores all data. Application settings, including encrypted API credentials for both firewalls and Panorama, are stored in a `settings` table.
* **Security:** The password encryption key is stored in the `secret.key` file. **Important:** Do not delete this file, as it is required to decrypt the stored credentials. If you back up the database, back up this key file as well.
* **PDF Generation:** The PDF reports are generated entirely on the server using **Matplotlib** to create the chart images and **FPDF2** to assemble the document.

---
