import asyncio

async def scan_port(ip, port):
    try:
        reader, writer = await asyncio.open_connection(ip, port)
        writer.close()
        return port
    except:
        return None

async def scan_ports(ip, ports):
    tasks = [scan_port(ip, port) for port in ports]
    results = await asyncio.gather(*tasks)
    return [p for p in results if p]
