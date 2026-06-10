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

def get_exe_dir():
    """Returns the directory where the .exe (or script) is located."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))

def load_config():
    config_path = os.path.join(get_exe_dir(), 'config.json')
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        required = ["LISTEN_HOST", "LISTEN_PORT", "CONNECT_IP", "CONNECT_PORT"]
        for key in required:
            if key not in config:
                raise ValueError(f"Missing config key: {key}")
        return config
    except FileNotFoundError:
        logger.error(f"Config file not found: {config_path}")
        sys.exit(1)
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON in config file: {config_path}")
        sys.exit(1)

# Load Config
config = load_config()
LISTEN_HOST = config["LISTEN_HOST"]
LISTEN_PORT = config["LISTEN_PORT"]
CONNECT_IP = config["CONNECT_IP"]
CONNECT_PORT = config["CONNECT_PORT"]
TLS_VERSION = config.get("TLS_VERSION", "1.2")
SNI_LIST = config.get("SNI_LIST", ["www.google.com"])
MAX_RETRIES = config.get("MAX_RETRIES", 3)
RETRY_DELAY = config.get("RETRY_DELAY", 2)

# Determine Interface IP and Socket Family
if ':' in CONNECT_IP:
    INTERFACE_IP = get_default_interface_ip(CONNECT_IP)
    FAMILY = socket.AF_INET6
else:
    INTERFACE_IP = get_default_interface_ip(CONNECT_IP)
    FAMILY = socket.AF_INET

if not INTERFACE_IP:
    logger.error("Could not determine default interface IP.")
    sys.exit(1)

DATA_MODE = "tls"
BYPASS_METHOD = "wrong_seq"

# Global connection tracker
fake_injective_connections: dict[tuple, FakeInjectiveConnection] = {}

async def relay_main_loop(sock_1: socket.socket, sock_2: socket.socket, peer_task: asyncio.Task,
                          first_prefix_data: bytes):
    """Relays data between two sockets."""
    try:
        loop = asyncio.get_running_loop()
        while True:
            try:
                data = await loop.sock_recv(sock_1, 65575)
                if not data:
                    raise ValueError("EOF")
                
                if first_prefix_data:
                    data = first_prefix_data + data
                    first_prefix_data = b""
                
                sent_len = await loop.sock_sendall(sock_2, data)
                if sent_len != len(data):
                    raise ValueError("Incomplete send")
            except asyncio.CancelledError:
                break
            except Exception:
                logger.debug(f"Relay loop error: {sock_1.getpeername()} -> {sock_2.getpeername()}")
                sock_1.close()
                sock_2.close()
                peer_task.cancel()
                return
    except Exception:
        logger.error("Relay main loop error!")

async def handle(incoming_sock: socket.socket, incoming_remote_addr):
    """Handles a new incoming connection with retry logic."""
    outgoing_sock = None
    try:
        loop = asyncio.get_running_loop()
        
        # Dynamic SNI Rotation
        fake_sni = random.choice(SNI_LIST)
        logger.info(f"New connection from {incoming_remote_addr}, using SNI: {fake_sni}")
        
        # Generate Fake TLS Data
        if DATA_MODE == "tls":
            fake_data = ClientHelloMaker.get_client_hello(fake_sni, TLS_VERSION)
        else:
            logger.error("Impossible mode!")
            incoming_sock.close()
            return

        # Connect to Remote with Retry
        retries = 0
        while retries < MAX_RETRIES:
            try:
                outgoing_sock = socket.socket(FAMILY, socket.SOCK_STREAM)
                outgoing_sock.setblocking(False)
                outgoing_sock.bind((INTERFACE_IP, 0))
                outgoing_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
                outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
                outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
                
                src_port = outgoing_sock.getsockname()[1]
                
                fake_injective_conn = FakeInjectiveConnection(
                    outgoing_sock, INTERFACE_IP, CONNECT_IP, src_port, CONNECT_PORT,
                    fake_data, BYPASS_METHOD, incoming_sock
                )
                fake_injective_connections[fake_injective_conn.id] = fake_injective_conn
                
                await loop.sock_connect(outgoing_sock, (CONNECT_IP, CONNECT_PORT))
                break # Success
            except Exception as e:
                logger.warning(f"Connection to {CONNECT_IP}:{CONNECT_PORT} failed (Attempt {retries+1}/{MAX_RETRIES}): {e}")
                retries += 1
                if outgoing_sock:
                    outgoing_sock.close()
                if retries < MAX_RETRIES:
                    await asyncio.sleep(RETRY_DELAY)
                else:
                    logger.error(f"Max retries reached for {incoming_remote_addr}")
                    incoming_sock.close()
                    return

        # Wait for Fake Handshake Completion
        if BYPASS_METHOD == "wrong_seq":
            try:
                await asyncio.wait_for(fake_injective_conn.t2a_event.wait(), 5.0)
                if fake_injective_conn.t2a_msg == "unexpected_close":
                    raise ValueError("Unexpected close during handshake")
                if fake_injective_conn.t2a_msg != "fake_data_ack_recv":
                    raise ValueError(f"Unexpected t2a msg: {fake_injective_conn.t2a_msg}")
            except asyncio.TimeoutError:
                logger.error("Handshake timeout")
                fake_injective_conn.monitor = False
                del fake_injective_connections[fake_injective_conn.id]
                outgoing_sock.close()
                incoming_sock.close()
                return
            except Exception:
                fake_injective_conn.monitor = False
                del fake_injective_connections[fake_injective_conn.id]
                outgoing_sock.close()
                incoming_sock.close()
                return
        else:
            logger.error("Unknown bypass method!")
            return

        # Clean up injector reference
        fake_injective_conn.monitor = False
        del fake_injective_connections[fake_injective_conn.id]

        # Start Relay
        oti_task = asyncio.create_task(
            relay_main_loop(outgoing_sock, incoming_sock, asyncio.current_task(), b"")
        )
        await relay_main_loop(incoming_sock, outgoing_sock, oti_task, b"")
        
    except Exception:
        logger.error(f"Handle error: {traceback.format_exc()}")
        try:
            incoming_sock.close()
            if outgoing_sock:
                outgoing_sock.close()
        except:
            pass

async def main():
    mother_sock = socket.socket(FAMILY, socket.SOCK_STREAM)
    mother_sock.setblocking(False)
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mother_sock.bind((LISTEN_HOST, LISTEN_PORT))
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    mother_sock.listen()
    
    logger.info(f"SNI Proxy listening on {LISTEN_HOST}:{LISTEN_PORT}")
    logger.info(f"Forwarding to {CONNECT_IP}:{CONNECT_PORT}")
    
    loop = asyncio.get_running_loop()
    
    while True:
        try:
            incoming_sock, addr = await loop.sock_accept(mother_sock)
            incoming_sock.setblocking(False)
            incoming_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
            incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
            incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            asyncio.create_task(handle(incoming_sock, addr))
        except Exception:
            logger.error(f"Accept error: {traceback.format_exc()}")

def signal_handler(sig, frame):
    logger.info("Shutting down gracefully...")
    # Close all connections
    for conn_id, conn in fake_injective_connections.items():
        try:
            conn.sock.close()
            conn.peer_sock.close()
        except:
            pass
    fake_injective_connections.clear()
    sys.exit(0)

if __name__ == "__main__":
    # Setup Signal Handlers for Graceful Shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    w_filter = "tcp and " + "(" + "(ip.SrcAddr " + INTERFACE_IP + " and ip.DstAddr " + CONNECT_IP + ")" + " or " + "(ip.SrcAddr " + CONNECT_IP + " and ip.DstAddr " + INTERFACE_IP + ")" + ")"
    
    fake_tcp_injector = FakeTcpInjector(w_filter, fake_injective_connections)
    threading.Thread(target=fake_tcp_injector.run, args=(), daemon=True).start()
    
    print("@ItsWanheda - SNI Proxy Overhauled")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down...")