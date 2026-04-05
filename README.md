# Enterprise Network Scanner 🚀

A custom-built enterprise-level network reconnaissance tool inspired by Nmap, with enhanced intelligence features.

## 🔥 Features
- Network discovery (ARP scan with ICMP ping fallback - no root required)
- Async port scanning
- Service banner grabbing
- Risk assessment
- Attack path prediction
- Exploit suggestions
- Web security analysis
- Server security checks
- Cloud detection
- JSON-based reporting
- Modular architecture
- Web UI via FastAPI

## ⚙️ Tech Stack
- Python 3.8+
- Scapy
- FastAPI
- Asyncio
- SQLite

## 🚀 Installation

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## 🚀 Usage

### CLI Tool
```bash
sudo python main.py  # Requires sudo for ARP scan
```

### Web API
```bash
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000  # ARP scan will fail without sudo, but other features work
# Or with sudo for full functionality: sudo python -m uvicorn api.main:app --host 0.0.0.0 --port 8000
```

Open http://localhost:8000/ui for the web interface.

Username: admin
Password: 1234

## 📊 Reports
Scans are saved to `reports/` as JSON files.
Database stored in `scanner.db`.

## ⚠️ Notes
- ARP scanning requires root privileges
- For production, change default credentials
- Customize target network in the code
