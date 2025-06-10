import socket
import logging

def grab_banner(target_host, port, timeout=3):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((target_host, port))
        banner = s.recv(1024).decode(errors='ignore').strip()
        s.close()
        logging.debug(f"Banner on port {port}: {banner}")
        return banner
    except Exception as e:
        logging.debug(f"Failed to grab banner on port {port}: {e}")
        return None
