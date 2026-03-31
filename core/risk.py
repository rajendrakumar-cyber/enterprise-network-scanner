def calculate_risk(ports, services):
    score = 0

    risky_ports = [21, 23, 445, 3389]

    for p in ports:
        if p in risky_ports:
            score += 2

    for banner in services.values():
        if banner:
            if "Apache 2.4.49" in banner:
                score += 5
            if "OpenSSH" in banner:
                score += 1

    return min(score, 10)
