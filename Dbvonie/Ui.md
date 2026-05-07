Build a modern, responsive web dashboard UI for a cybersecurity platform called "NetScan".

## Purpose

The platform allows users to scan their local network, discover connected devices, analyze open ports, and generate security reports.

## Pages to include

### 1. Authentication Page

* Clean login page
* Fields: email, password
* Buttons: Login, "Login with GitHub"
* Minimal, secure design (dark theme \ light theme toggle)

### 2. Main Dashboard

* Sidebar navigation (Dashboard, Scan, Reports, Settings, Logout)
* Top bar with user info and notifications

### 3. Admin portal (only for admin users):
* User management
* System settings
* Logs and monitoring for activity made by users

#### Dashboard content:

* Summary cards:

  * Total devices found
  * Active devices
  * Open ports detected
  * Alerts count

* Network devices table:
  Columns:

  * IP Address
  * MAC Address
  * Manufacturer (vendor)
  * Status (online/offline)
  * Risk level (low / medium / high)

* Visualizations:

  * Pie chart (device types or vendors)
  * Bar chart (open ports frequency)

* Real-time scan button:
  "Start Scan"

### 3. Scan Page

* Button to launch scan
* Loading animation while scanning
* Live results appearing dynamically

### 4. Reports Page

* List of previous scans
* Button to download report (PDF/DOCX)
* Preview of report summary

### 5. Alerts / Notifications

* Show new devices detected
* Highlight suspicious ports (e.g., 22, 445)

## UI/UX Requirements

* Dark mode (cybersecurity style)
* Light mode (cybersecurity style)
* Modern design (similar to hacking dashboards)
* Smooth animations
* Responsive (desktop + mobile)
* Use cards, tables, and charts
* Minimalistic, not cluttered
* Maybe a background with a specific pattern (e.g., matrix code, circuit board) but subtle...

## Technical Requirements

* Use React (preferred) or simple HTML/CSS/JS
* Use TailwindCSS for styling
* Use reusable components
* Prepare frontend to connect to a Flask API (REST endpoints like /scan, /devices, /reports)

## Extra

* Add subtle glow/neon effects for cybersecurity aesthetic
* Clean and professional (not childish hacker style)
* Focus on readability and usability

Return clean, structured code.
