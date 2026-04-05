from scapy.all import ARP, Ether, srp
import subprocess
import ipaddress

def arp_scan(ip_range):
    try:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
        result = srp(packet, timeout=2, verbose=0)[0]

        devices = []
        for sent, received in result:
            devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc
            })

        return devices
    except PermissionError:
        print("[!] ARP scan requires root privileges. Run with sudo.")
        return []
    except Exception as e:
        print(f"[!] ARP scan failed: {e}")
        return []


def ping_sweep(ip_range):
    """Alternative host discovery using system ping (no root required)"""
    try:
        devices = []
        
        # Parse CIDR to get IPs
        network = ipaddress.ip_network(ip_range, strict=False)
        # Limit to first 10 IPs for demo
        ips_to_ping = list(network.hosts())[:10]
        
        for ip in ips_to_ping:
            ip_str = str(ip)
            try:
                # Use system ping with timeout
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', ip_str],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                if result.returncode == 0:
                    devices.append({
                        "ip": ip_str,
                        "mac": "Unknown (ping discovery)"
                    })
            except subprocess.TimeoutExpired:
                continue
            except Exception:
                continue
        
        return devices
    except Exception as e:
        print(f"[!] Ping sweep failed: {e}")
        return []
