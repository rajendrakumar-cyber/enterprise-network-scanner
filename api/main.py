from fastapi import FastAPI
import asyncio

from core.discovery import arp_scan
from core.portscan import scan_ports
from core.service import grab_banner
from core.risk import calculate_risk
from core.attack_path import predict_attack
from core.exploit_suggest import suggest_exploits
from core.security_analysis import analyze_web_security, analyze_server_security, detect_cloud

app = FastAPI()

TARGET = "192.168.1.0/24"
PORTS = [22, 80, 443, 445, 3389]


@app.get("/")
def home():
    return {"message": "Enterprise Scanner API Running"}


@app.get("/scan")
async def run_scan():
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
            "risk": risk,
            "services": services,
            "attack_paths": attack_paths,
            "exploits": exploits,
            "web_security": web_security,
            "server_issues": server_issues,
            "cloud": cloud_info
        })

    return {"results": results}
