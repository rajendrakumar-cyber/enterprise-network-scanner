import socket

def analyze_web_security(ip, port):
    result = {
        "headers": {},
        "issues": []
    }

    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((ip, port))

        s.send(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
        response = s.recv(4096).decode(errors="ignore")

        headers = response.split("\r\n")

        for h in headers:
            if ":" in h:
                key, value = h.split(":", 1)
                result["headers"][key.strip()] = value.strip()

        if "X-Frame-Options" not in result["headers"]:
            result["issues"].append("Missing X-Frame-Options")

        if "Content-Security-Policy" not in result["headers"]:
            result["issues"].append("Missing CSP")

        if "Server" in result["headers"]:
            result["server"] = result["headers"]["Server"]

        return result

    except:
        return None


def analyze_server_security(ports):
    issues = []

    if 21 in ports:
        issues.append("FTP open (insecure)")

    if 23 in ports:
        issues.append("Telnet open (very insecure)")

    if 445 in ports:
        issues.append("SMB exposed (ransomware risk)")

    if 3389 in ports:
        issues.append("RDP exposed (bruteforce risk)")

    return issues


def detect_cloud(services):
    cloud = []

    for banner in services.values():
        if not banner:
            continue

        banner = banner.lower()

        if "cloudflare" in banner:
            cloud.append("Cloudflare")

        if "amazon" in banner or "aws" in banner:
            cloud.append("AWS")

        if "azure" in banner:
            cloud.append("Azure")

    return list(set(cloud))
