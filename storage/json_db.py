import json
from datetime import datetime

def save_scan(data):
    filename = f"reports/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    
    print(f"[+] Saved: {filename}")
