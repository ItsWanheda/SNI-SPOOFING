# SNI.py
import asyncio
import os
import socket
import sys
import traceback
import threading
import json
import logging
import signal
import random
from utils.Network import get_default_interface_ip
from utils.Packet import ClientHelloMaker
from Fake_Handshake import FakeInjectiveConnection, FakeTcpInjector

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Single lock guarding the shared connections registry (asyncio loop, pydivert thread, signal handler)
_connections_lock = threading.Lock()


def get_exe_dir():
    """Returns the directory where the .exe (or script) is located."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def _validate_port(p, name):
    if not isinstance(p, int) or not (0 < p < 65536):
        raise ValueError(f"{name} must be an integer in 1..65535, got {p!r}")


def _validate_ip(ip, name):
    if not isinstance(ip, str) or not ip:
        raise ValueError(f"{name} must be a non-empty string")
    family = socket.AF_INET6 if ':' in ip else socket.AF_INET
    try:
        socket.inet_pton(family, ip)
    except OSError as e:
        raise ValueError(f"Invalid IP in {name}={ip!r}: {e}")


def _validate_config(cfg):
    _validate_ip(cfg["LISTEN_HOST"], "LISTEN_HOST")
    _validate_port(cfg["LISTEN_PORT"], "LISTEN_PORT")
    _validate_ip(cfg["CONNECT_IP"], "CONNECT_IP")
    _validate_port(cfg["CONNECT_PORT"], "CONNECT_PORT")

    tls = cfg.get("TLS_VERSION", "1.2")
    if tls not in ("1.2", "1.3"):
        raise ValueError(f"TLS_VERSION must be '1.2' or '1.3', got {tls!r}")

    sni_list = cfg.get("SNI_LIST", ["www.google.com"])
    if not isinstance(sni_list, list) or not sni_list:
        raise ValueError("SNI_LIST must be a non-empty list")
    for s in sni_list:
        if not isinstance(s, str) or not s or len(s) > 255:
            raise ValueError("SNI_LIST entries must be non-empty strings (<=255 chars)")

    retries = cfg.get("MAX_RETRIES", 3)
    if not isinstance(retries, int) or retries < 0 or retries > 100:
        raise ValueError("MAX_RETRIES must be 0..100")

    delay = cfg.get("RETRY_DELAY", 2)
    if not isinstance(delay, (int, float)) or delay < 0 or delay > 60:
        raise ValueError("RETRY_DELAY must be 0..60 seconds")


def load_config():
    config_path = os.path.join(get_exe_dir(), 'config.json')
    try:
        with open(config_path, 'r') as f:
            cfg = json.load(f)
    except FileNotFoundError:
        logger.error(f"Config file not found: {config_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in config file {config_path}: {e}")
        sys.exit(1)

    required = ["LISTEN_HOST", "LISTEN_PORT", "CONNECT_IP", "CONNECT_PORT"]
    for key in required:
        if key not in cfg:
            logger.error(f"Missing config key: {key}")
            sys.exit(1)

    try:
        _validate_config(cfg)
    except ValueError as e:
        logger.error(f"Invalid configuration: {e}")
        sys.exit(1)
    return cfg


# Load Config
config = load_config()
LISTEN_HOST   = config["LISTEN_HOST"]
LISTEN_PORT   = config["LISTEN_PORT"]
CONNECT_IP    = config["CONNECT_IP"]
CONNECT_PORT  = config["CONNECT_PORT"]
TLS_VERSION   = config.get("TLS_VERSION", "1.2")
SNI_LIST      = config.get("SNI_LIST", ["www.google.com"])
MAX_RETRIES   = config.get("MAX_RETRIES", 3)
RETRY_DELAY   = config.get("RETRY_DELAY", 2)

# Determine Interface IP and Socket Family
IS_IPV6 = ':' in CONNECT_IP
INTERFACE_IP = get_default_interface_ip(CONNECT_IP)
FAMILY = socket.AF_INET6 if IS_IPV6 else socket.AF_INET

if not INTERFACE_IP:
    logger.error("Could not determine default interface IP.")
    sys.exit(1)

DATA_MODE = "tls"
BYPASS_METHOD = "wrong_seq"

if BYPASS_METHOD not in ("wrong_seq",):
    logger.error(f"Unsupported BYPASS_METHOD: {BYPASS_METHOD}")
    sys.exit(1)

# Shared registry (thread-safe via _connections_lock)
fake_injective_connections: dict[tuple, FakeInjectiveConnection] = {}


def _safe_close(sock):
    if sock is None:
        return
    try:
        sock.close()
    except OSError:
        pass


def _register(conn):
    with _connections_lock:
        fake_injective_connections[conn.id] = conn


def _unregister(conn_id):
    with _connections_lock:
        fake_injective_connections.pop(conn_id, None)


async def relay_main_loop(sock_1: socket.socket, sock_2: socket.socket,
                          first_prefix_data: bytes = b""):
    """Bidirectional-friendly relay: forwards bytes from sock_1 to sock_2 until EOF/error."""
    loop = asyncio.get_running_loop()
    try:
        if first_prefix_data:
            await loop.sock_sendall(sock_2, first_prefix_data)
        while True:
            data = await loop.sock_recv(sock_1, 65575)
            if not data:
                return  # clean EOF
            # sock_sendall returns None on success; do not compare its return value
            await loop.sock_sendall(sock_2, data)
    except asyncio.CancelledError:
        raise
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        logger.debug(f"Relay closed ({sock_1.getpeername() if sock_1.fileno() != -1 else '?'} -> "
                     f"{sock_2.getpeername() if sock_2.fileno() != -1 else '?'}): {e}")
    except Exception:
        logger.exception("Unexpected relay error")
    finally:
        _safe_close(sock_1)
        _safe_close(sock_2)


def _configure_keepalive(sock: socket.socket):
    """Best-effort TCP keepalive setup."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    except OSError as e:
        logger.debug(f"Keepalive not fully supported on this socket: {e}")


async def handle(incoming_sock: socket.socket, incoming_remote_addr):
    """Handles a new incoming connection with retry logic."""
    outgoing_sock = None
    fake_injective_conn = None
    relay_tasks = []
    try:
        loop = asyncio.get_running_loop()

        fake_sni = random.choice(SNI_LIST)
        logger.info(f"New connection from {incoming_remote_addr}, using SNI: {fake_sni}")

        if DATA_MODE != "tls":
            logger.error(f"Unsupported DATA_MODE: {DATA_MODE!r}")
            return

        try:
            fake_data = ClientHelloMaker.get_client_hello(fake_sni, TLS_VERSION)
        except Exception as e:
            logger.error(f"Failed to build fake ClientHello: {e}")
            return

        # Connect to remote with retry. Build the FakeInjectiveConnection BEFORE the
        # connect call so we can compute src_port for the registry key, but only register
        # it AFTER successful connect (avoids the injector racing against an unconnected sock).
        connected = False
        for attempt in range(MAX_RETRIES):
            attempt_sock = None
            attempt_conn = None
            try:
                attempt_sock = socket.socket(FAMILY, socket.SOCK_STREAM)
                attempt_sock.setblocking(False)
                attempt_sock.bind((INTERFACE_IP, 0))
                _configure_keepalive(attempt_sock)

                src_port = attempt_sock.getsockname()
                attempt_conn = FakeInjectiveConnection(
                    attempt_sock, INTERFACE_IP, CONNECT_IP, src_port, CONNECT_PORT,
                    fake_data, BYPASS_METHOD, incoming_sock
                )
                await loop.sock_connect(attempt_sock, (CONNECT_IP, CONNECT_PORT))
                # Mark ready AND register atomically under the lock
                with _connections_lock:
                    attempt_conn.ready = True
                    fake_injective_connections[attempt_conn.id] = attempt_conn
                outgoing_sock = attempt_sock
                fake_injective_conn = attempt_conn
                connected = True
                break
            except Exception as e:
                logger.warning(f"Connect to {CONNECT_IP}:{CONNECT_PORT} failed "
                               f"(attempt {attempt + 1}/{MAX_RETRIES}): {e}")
                if attempt_conn is not None:
                    attempt_conn.monitor = False
                _safe_close(attempt_sock)
                if attempt + 1 < MAX_RETRIES:
                    await asyncio.sleep(RETRY_DELAY)

        if not connected:
            logger.error(f"Max retries reached for {incoming_remote_addr}")
            _safe_close(incoming_sock)
            return

        # Wait for fake-handshake completion
        try:
            await asyncio.wait_for(fake_injective_conn.t2a_event.wait(), timeout=10.0)
        except asyncio.TimeoutError:
            logger.error(f"Handshake timeout for {incoming_remote_addr}")
            return

        if fake_injective_conn.t2a_msg == "unexpected_close":
            logger.warning(f"Handshake closed unexpectedly for {incoming_remote_addr}")
            return
        if fake_injective_conn.t2a_msg != "fake_data_ack_recv":
            logger.error(f"Unexpected handshake result: {fake_injective_conn.t2a_msg}")
            return

        # Stop monitoring and unregister so the injector thread stops touching this conn
        fake_injective_conn.monitor = False
        _unregister(fake_injective_conn.id)
        fake_injective_conn = None

        # Bidirectional relay: when one direction ends, cancel the other
        oti = asyncio.create_task(relay_main_loop(outgoing_sock, incoming_sock))
        ito = asyncio.create_task(relay_main_loop(incoming_sock, outgoing_sock))
        relay_tasks = [oti, ito]
        done, pending = await asyncio.wait(relay_tasks, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        for t in pending:
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass

    except Exception:
        logger.error(f"Handle error: {traceback.format_exc()}")
    finally:
        # Cleanup: tear down injector state and sockets
        if fake_injective_conn is not None:
            fake_injective_conn.monitor = False
            _unregister(fake_injective_conn.id)
        for t in relay_tasks:
            if not t.done():
                t.cancel()
        for t in relay_tasks:
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
        _safe_close(incoming_sock)
        _safe_close(outgoing_sock)


async def main():
    mother_sock = socket.socket(FAMILY, socket.SOCK_STREAM)
    try:
        mother_sock.setblocking(False)
        mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _configure_keepalive(mother_sock)
        mother_sock.bind((LISTEN_HOST, LISTEN_PORT))
        mother_sock.listen(128)
    except OSError as e:
        logger.error(f"Failed to bind {LISTEN_HOST}:{LISTEN_PORT}: {e}")
        sys.exit(1)

    logger.info(f"SNI Proxy listening on {LISTEN_HOST}:{LISTEN_PORT}")
    logger.info(f"Forwarding to {CONNECT_IP}:{CONNECT_PORT} (interface: {INTERFACE_IP})")

    loop = asyncio.get_running_loop()
    background_tasks: set[asyncio.Task] = set()

    try:
        while True:
            try:
                incoming_sock, addr = await loop.sock_accept(mother_sock)
            except asyncio.CancelledError:
                break
            except OSError as e:
                logger.error(f"Accept error: {e}")
                continue
            try:
                incoming_sock.setblocking(False)
                _configure_keepalive(incoming_sock)
            except OSError as e:
                logger.debug(f"Could not configure keepalive: {e}")
            task = asyncio.create_task(handle(incoming_sock, addr))
            background_tasks.add(task)
            task.add_done_callback(background_tasks.discard)
    finally:
        for task in list(background_tasks):
            task.cancel()
        for task in list(background_tasks):
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        _safe_close(mother_sock)


def signal_handler(sig, frame):
    """Best-effort graceful shutdown; safe to call from main thread."""
    logger.info("Shutting down gracefully...")
    with _connections_lock:
        for conn in list(fake_injective_connections.values()):
            try:
                conn.monitor = False
            except Exception:
                pass
            _safe_close(conn.sock)
            _safe_close(conn.peer_sock)
        fake_injective_connections.clear()
    # Bypass any still-running asyncio.run() cleanly
    os._exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Build WinDivert filter safely (no string concat with raw IPs)
    if IS_IPV6:
        w_filter = (
            f"tcp and "
            f"(((ipv6.SrcAddr == {INTERFACE_IP} and ipv6.DstAddr == {CONNECT_IP}) "
            f"or (ipv6.SrcAddr == {CONNECT_IP} and ipv6.DstAddr == {INTERFACE_IP})))"
        )
    else:
        w_filter = (
            f"tcp and "
            f"(((ip.SrcAddr == {INTERFACE_IP} and ip.DstAddr == {CONNECT_IP}) "
            f"or (ip.SrcAddr == {CONNECT_IP} and ip.DstAddr == {INTERFACE_IP})))"
        )

    fake_tcp_injector = FakeTcpInjector(w_filter, fake_injective_connections, _connections_lock)
    threading.Thread(target=fake_tcp_injector.run, args=(), daemon=True).start()

    print("@ItsWanheda - SNI Proxy Overhauled")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down...")