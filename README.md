# Network Security Scanner & Visual Dashboard

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Framework](https://img.shields.io/badge/Framework-Flask-lightgrey.svg)](https://flask.palletsprojects.com/)

A professional-grade, lightweight network scanner for cybersecurity auditing. This tool combines rapid host discovery with advanced device fingerprinting and a modern web-based dashboard for real-time visualization.

## 🚀 Key Features

- **Advanced Host Discovery**: Fast ARP-based scanning to discover all active devices on the local network.
- **Deep Device Fingerprinting**:
  - **MAC OUI Lookup**: Identify device manufacturers.
  - **Service Discovery**: Scan common ports and extract service banners.
  - **OS Classification**: Heuristic classification of device operating systems.
  - **Protocol Analysis**: DHCP, HTTP, and TCP fingerprinting for high-accuracy identification.
- **Modern Dashboard**: Visual representation of network topology and device details using Flask.
- **Secure by Design**: Built-in authentication (Bcrypt/OAuth), input validation, and rate limiting.
- **Flexible Exports**: Save scan results to SQLite and export to JSON or CSV formats.
- **Report Generation**: Professional PDF/HTML reports for audit documentation.

## 🛠️ Project Structure

- `scanner/`: Core Python scanning engine.
  - `core/`: ARP and Port scanning implementation using Scapy.
  - `fingerprint/`: OS and service identification logic.
- `web/`: (Planned/In-Progress) Flask-based dashboard.
- `reports/`: Generated PDF and HTML audit reports.

## 🚦 Quick Start

### Prerequisites

- Python 3.8+
- `sudo` privileges (required for raw socket access / ARP scanning)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/pfe.git
   cd pfe
   ```

2. Set up the environment and install dependencies:
   ```bash
   make install
   ```

### Usage

**Run a basic scan (auto-detects network):**
```bash
make run-sudo
```

**Scan a specific network:**
```bash
make run NETWORK=192.168.1.0/24
```

**List previous scans:**
```bash
make run-list
```

## 🔒 Security

This project implements several security best practices:
- **Authentication**: Dashboard access restricted via Bcrypt or GitHub OAuth.
- **Input Validation**: Rigorous validation of network ranges and user inputs.
- **Data Protection**: Secure storage of scan results in an encrypted or restricted SQLite database.

## 👥 Contributors

- **ABIED Youssef** (@Dna9a) - Scanner Engine, Scapy Logic, Security & Reports.
- **EL-BARAZI Meriem** (@Dbvonie) - Flask Backend, UI/UX, Dashboard & Authentication.

---
*Developed as a PFE (Projet de Fin d'Études) project.*




