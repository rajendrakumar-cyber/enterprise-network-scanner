import socket

def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))

        try:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        except:
            pass

        banner = s.recv(1024)
        return banner.decode(errors="ignore").strip()

    except:
        return None
