import asyncio
from core.discovery import arp_scan
from core.portscan import scan_ports
from storage.json_db import save_scan

TARGET = "192.168.1.0/24"
PORTS = [22, 80, 443, 445, 3389]

async def main():
    print("[*] Discovering devices...")
    devices = arp_scan(TARGET)

    results = []

    for device in devices:
        ip = device["ip"]
        print(f"[*] Scanning {ip}")

        open_ports = await scan_ports(ip, PORTS)

        results.append({
            "ip": ip,
            "mac": device["mac"],
            "ports": open_ports
        })

    scan_data = {
        "target": TARGET,
        "hosts": results
    }

    save_scan(scan_data)

asyncio.run(main())
