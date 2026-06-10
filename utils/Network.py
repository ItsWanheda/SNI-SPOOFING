# Network.py
import socket

def get_default_interface_ip(target_ip: str) -> str:
    """
    Returns the default interface IP (IPv4 or IPv6) based on the target address.
    """
    try:
        # Determine if target is IPv4 or IPv6 to set socket family
        if ':' in target_ip:
            family = socket.AF_INET6
        else:
            family = socket.AF_INET
            
        s = socket.socket(family, socket.SOCK_DGRAM)
        s.connect((target_ip, 53))
        ip = s.getsockname()[0]
    except OSError:
        return ""
    finally:
        s.close()
    return ip