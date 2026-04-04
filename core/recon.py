import socket

def dns_lookup(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None


def subdomain_enum(domain):
    subs = ["www", "mail", "api", "dev", "test"]
    found = []

    for sub in subs:
        try:
            ip = socket.gethostbyname(f"{sub}.{domain}")
            found.append(f"{sub}.{domain} → {ip}")
        except:
            pass

    return found
