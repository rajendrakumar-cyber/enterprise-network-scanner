from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import asyncio
import json

from core.discovery import arp_scan
from core.portscan import scan_ports
from core.service import grab_banner
from core.risk import calculate_risk
from core.attack_path import predict_attack
from core.exploit_suggest import suggest_exploits
from core.security_analysis import analyze_web_security, analyze_server_security, detect_cloud

from database.db import init_db, save_to_db, get_scans
from core.recon import dns_lookup, subdomain_enum

app = FastAPI()

# 🔐 AUTH
security = HTTPBasic()
USERNAME = "admin"
PASSWORD = "1234"

def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    if credentials.username != USERNAME or credentials.password != PASSWORD:
        raise HTTPException(status_code=401, detail="Unauthorized")


# 🔥 INIT DB
init_db()

TARGET = "192.168.1.0/24"
PORTS = [22, 80, 443, 445, 3389]


@app.get("/")
def home():
    return {"message": "Enterprise Scanner API Running"}


@app.get("/ui", response_class=HTMLResponse)
def ui():
    with open("api/ui.html") as f:
        return f.read()


@app.get("/scan")
async def run_scan(user: str = Depends(authenticate)):
    devices = arp_scan(TARGET)
    results = []

    for device in devices:
        ip = device["ip"]

        open_ports = await scan_ports(ip, PORTS)

        services = {}
        for port in open_ports:
            banner = grab_banner(ip, port)
            services[port] = banner

        risk = calculate_risk(open_ports, services)
        attack_paths = predict_attack(open_ports, services)
        exploits = suggest_exploits(services)

        web_security = {}
        for port in open_ports:
            if port in [80, 443]:
                web_security[port] = analyze_web_security(ip, port)

        server_issues = analyze_server_security(open_ports)
        cloud_info = detect_cloud(services)

        results.append({
            "ip": ip,
            "ports": open_ports,
            "services": services,
            "risk": risk,
            "attack_paths": attack_paths,
            "exploits": exploits,
            "web_security": web_security,
            "server_issues": server_issues,
            "cloud": cloud_info
        })

    # 🔥 SAVE TO DB
    save_to_db(TARGET, json.dumps(results))

    return {"results": results}


@app.get("/history")
def history():
    return {"data": get_scans()}


@app.get("/recon/{domain}")
def recon(domain: str):
    return {
        "ip": dns_lookup(domain),
        "subdomains": subdomain_enum(domain)
    }
