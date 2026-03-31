import json
import os

def load_last_scan():
    if not os.path.exists("reports"):
        return None

    files = sorted(os.listdir("reports"))

    if not files:
        return None

    latest = files[-1]

    with open(f"reports/{latest}", "r") as f:
        return json.load(f)


def compare_scans(old, new):
    if not old:
        return ["[INFO] First scan — no previous data"]

    changes = []

    old_hosts = {h['ip']: h for h in old['hosts']}

    for host in new['hosts']:
        ip = host['ip']

        if ip not in old_hosts:
            changes.append(f"[NEW DEVICE] {ip}")
        else:
            old_ports = set(old_hosts[ip]['ports'])
            new_ports = set(host['ports'])

            added = new_ports - old_ports

            if added:
                changes.append(f"[NEW PORTS] {ip} → {list(added)}")

    return changes
