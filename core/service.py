import asyncio
import socket

async def grab_banner(ip, port):
    loop = asyncio.get_event_loop()
    try:
        # Use loop.run_in_executor to run blocking socket operations in a thread
        reader, writer = await asyncio.open_connection(ip, port)
        writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
        await writer.drain()
        data = await reader.read(1024)
        writer.close()
        await writer.wait_closed()
        return data.decode(errors="ignore").strip()
    except:
        return None
