# Fake_Handshake.py
import asyncio
import socket
import sys
import threading
import time
import logging
from pydivert import Packet
from Log_Monitoring import MonitorConnection
from Injector import TcpInjector

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class FakeInjectiveConnection(MonitorConnection):
    def __init__(self, sock: socket.socket, src_ip, dst_ip,
                 src_port, dst_port, fake_data: bytes, bypass_method: str, peer_sock: socket.socket):
        super().__init__(sock, src_ip, dst_ip, src_port, dst_port)
        self.fake_data = fake_data
        self.sch_fake_sent = False
        self.fake_sent = False
        self.t2a_event = asyncio.Event()
        self.t2a_msg = ""
        self.bypass_method = bypass_method
        self.peer_sock = peer_sock
        try:
            self.running_loop = asyncio.get_running_loop()
        except RuntimeError:
            self.running_loop = None
        logger.debug(f"Connection {self.id} initialized with bypass method: {bypass_method}")

class FakeTcpInjector(TcpInjector):
    def __init__(self, w_filter: str, connections: dict[tuple, FakeInjectiveConnection]):
        super().__init__(w_filter)
        self.connections = connections
        logger.info("FakeTcpInjector started")

    def fake_send_thread(self, packet: Packet, connection: FakeInjectiveConnection):
        """Thread to inject fake data with a slight delay."""
        time.sleep(0.002)
        with connection.thread_lock:
            if not connection.monitor:
                return
            try:
                packet.tcp.psh = True
                packet.ip.packet_len = packet.ip.packet_len + len(connection.fake_data)
                packet.tcp.payload = connection.fake_data
                
                if packet.ipv4:
                    packet.ipv4.ident = (packet.ipv4.ident + 1) & 0xffff
                
                if connection.bypass_method == "wrong_seq":
                    packet.tcp.seq_num = (connection.syn_seq + 1 - len(packet.tcp.payload)) & 0xffffffff
                    connection.fake_sent = True
                    self.w.send(packet, True)
                    logger.debug(f"Fake data injected for {connection.id}")
            except Exception as e:
                logger.error(f"Error injecting fake data: {e}")

    def on_unexpected_packet(self, packet: Packet, connection: FakeInjectiveConnection, info_m: str):
        logger.warning(f"Unexpected packet for {connection.id}: {info_m}")
        connection.sock.close()
        connection.peer_sock.close()
        connection.monitor = False
        connection.t2a_msg = "unexpected_close"
        if connection.running_loop:
            connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)

    def on_inbound_packet(self, packet: Packet, connection: FakeInjectiveConnection):
        if connection.syn_seq == -1:
            self.on_unexpected_packet(packet, connection, "unexpected inbound packet, no syn sent!")
            return
        
        # Handle SYN-ACK
        if packet.tcp.ack and packet.tcp.syn and (not packet.tcp.rst) and (not packet.tcp.fin) and (
                len(packet.tcp.payload) == 0):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            
            if connection.syn_ack_seq != -1 and connection.syn_ack_seq != seq_num:
                self.on_unexpected_packet(packet, connection, "SYN-ACK seq mismatch!")
                return
            
            if ack_num != ((connection.syn_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(packet, connection, "SYN-ACK ack mismatch!")
                return
            
            connection.syn_ack_seq = seq_num
            self.w.send(packet, False)
            return

        # Handle ACK after fake data sent
        if packet.tcp.ack and (not packet.tcp.syn) and (not packet.tcp.rst) and (
                not packet.tcp.fin) and (len(packet.tcp.payload) == 0) and connection.fake_sent:
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            
            if connection.syn_ack_seq == -1 or ((connection.syn_ack_seq + 1) & 0xffffffff) != seq_num:
                self.on_unexpected_packet(packet, connection, "ACK seq mismatch!")
                return
            
            if ack_num != ((connection.syn_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(packet, connection, "ACK ack mismatch!")
                return
            
            connection.monitor = False
            connection.t2a_msg = "fake_data_ack_recv"
            if connection.running_loop:
                connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)
            logger.info(f"Fake data ACK received for {connection.id}. Handshake complete.")
            return

        self.on_unexpected_packet(packet, connection, "unexpected inbound packet during handshake")

    def on_outbound_packet(self, packet: Packet, connection: FakeInjectiveConnection):
        if connection.sch_fake_sent:
            self.on_unexpected_packet(packet, connection, "unexpected outbound packet after fake sent!")
            return
        
        # Handle SYN
        if packet.tcp.syn and (not packet.tcp.ack) and (not packet.tcp.rst) and (not packet.tcp.fin) and (
                len(packet.tcp.payload) == 0):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            
            if ack_num != 0:
                self.on_unexpected_packet(packet, connection, "SYN ack_num not zero!")
                return
            
            if connection.syn_seq != -1 and connection.syn_seq != seq_num:
                self.on_unexpected_packet(packet, connection, "SYN seq mismatch!")
                return
            
            connection.syn_seq = seq_num
            self.w.send(packet, False)
            return

        # Handle ACK (Handshake Complete)
        if packet.tcp.ack and (not packet.tcp.syn) and (not packet.tcp.rst) and (not packet.tcp.fin) and (
                len(packet.tcp.payload) == 0):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            
            if connection.syn_seq == -1 or ((connection.syn_seq + 1) & 0xffffffff) != seq_num:
                self.on_unexpected_packet(packet, connection, "ACK seq mismatch!")
                return
            
            if connection.syn_ack_seq == -1 or ack_num != ((connection.syn_ack_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(packet, connection, "ACK ack mismatch!")
                return
            
            self.w.send(packet, False)
            connection.sch_fake_sent = True
            threading.Thread(target=self.fake_send_thread, args=(packet, connection), daemon=True).start()
            return

        self.on_unexpected_packet(packet, connection, "unexpected outbound packet")

    def inject(self, packet: Packet):
        if packet.is_inbound:
            c_id = (packet.ip.dst_addr, packet.tcp.dst_port, packet.ip.src_addr, packet.tcp.src_port)
            try:
                connection = self.connections[c_id]
            except KeyError:
                self.w.send(packet, False)
            else:
                with connection.thread_lock:
                    if not connection.monitor:
                        self.w.send(packet, False)
                        return
                    self.on_inbound_packet(packet, connection)
        elif packet.is_outbound:
            c_id = (packet.ip.src_addr, packet.tcp.src_port, packet.ip.dst_addr, packet.tcp.dst_port)
            try:
                connection = self.connections[c_id]
            except KeyError:
                self.w.send(packet, False)
            else:
                with connection.thread_lock:
                    if not connection.monitor:
                        self.w.send(packet, False)
                        return
                    self.on_outbound_packet(packet, connection)
        else:
            logger.error("Impossible packet direction!")