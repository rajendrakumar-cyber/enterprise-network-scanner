def predict_attack(ports, services):
    attack_paths = []

    for port in ports:

        if port == 22:
            attack_paths.append({
                "port": 22,
                "service": "SSH",
                "attack": "Brute-force / Credential attack",
                "next_step": "Privilege escalation"
            })

        elif port == 80:
            attack_paths.append({
                "port": 80,
                "service": "HTTP",
                "attack": "Web vulnerability scan",
                "next_step": "Exploit web app (XSS, SQLi)"
            })

        elif port == 445:
            attack_paths.append({
                "port": 445,
                "service": "SMB",
                "attack": "SMB enumeration / EternalBlue",
                "next_step": "Remote code execution"
            })

        elif port == 3389:
            attack_paths.append({
                "port": 3389,
                "service": "RDP",
                "attack": "RDP brute-force",
                "next_step": "Full system access"
            })

    return attack_paths
