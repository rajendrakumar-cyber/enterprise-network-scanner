import asyncio
from core.discovery import arp_scan, ping_sweep
from core.portscan import scan_ports
from core.service import grab_banner
from core.risk import calculate_risk
from storage.json_db import save_scan
from storage.history import load_last_scan, compare_scans
from core.attack_path import predict_attack
from core.exploit_suggest import suggest_exploits

TARGET = "192.168.1.0/24"
PORTS = [22, 80, 443, 445, 3389]


async def main():
    print("[*] Discovering devices...")
    devices = arp_scan(TARGET)
    
    if not devices:
        print("[*] ARP scan found no devices, trying ping sweep...")
        devices = ping_sweep(TARGET)
    
    print(f"[+] Found {len(devices)} devices")

    results = []

    for device in devices:
        ip = device["ip"]
        print(f"[*] Scanning {ip}")

        open_ports = await scan_ports(ip, PORTS)

        # ✅ FIXED INDENTATION
        services = {}
        for port in open_ports:
            banner = await grab_banner(ip, port)
            services[port] = banner

        risk = calculate_risk(open_ports, services)

        attack_paths = predict_attack(open_ports, services)
        exploits = suggest_exploits(services)

        results.append({
            "ip": ip,
            "mac": device["mac"],
            "ports": open_ports,
            "services": services,
            "risk_score": risk,
            "attack_paths": attack_paths,
            "exploits": exploits
        })

    scan_data = {
        "target": TARGET,
        "hosts": results
    }

    # 🔥 CHANGE DETECTION
    old_scan = load_last_scan()
    changes = compare_scans(old_scan, scan_data)

    print("\n=== CHANGES DETECTED ===")
    for c in changes:
        print(c)

    save_scan(scan_data)


if __name__ == "__main__":
    asyncio.run(main())
