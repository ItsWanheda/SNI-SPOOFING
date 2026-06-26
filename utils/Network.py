# Network.py
import socket
import logging

logger = logging.getLogger(__name__)


def get_default_interface_ip(target_ip: str) -> str:
    """Return the local outbound interface IP used to reach ``target_ip``."""
    if not target_ip:
        return ""
    family = socket.AF_INET6 if ':' in target_ip else socket.AF_INET
    s = None
    try:
        s = socket.socket(family, socket.SOCK_DGRAM)
        # Connecting a UDP socket does not send packets; the kernel just picks a route.
        s.connect((target_ip, 53))
        return s.getsockname()
    except OSError as e:
        logger.debug(f"get_default_interface_ip failed for {target_ip!r}: {e}")
        return ""
    except Exception:
        logger.exception(f"Unexpected error in get_default_interface_ip({target_ip!r})")
        return ""
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass