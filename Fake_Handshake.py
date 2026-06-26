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

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

_VALID_BYPASS = ("wrong_seq",)


class FakeInjectiveConnection(MonitorConnection):
    def __init__(self, sock: socket.socket, src_ip, dst_ip,
                 src_port, dst_port, fake_data: bytes, bypass_method: str,
                 peer_sock: socket.socket):
        super().__init__(sock, src_ip, dst_ip, src_port, dst_port)
        if bypass_method not in _VALID_BYPASS:
            raise ValueError(f"Unsupported bypass_method: {bypass_method!r}")
        if not isinstance(fake_data, (bytes, bytearray)) or len(fake_data) == 0:
            raise ValueError("fake_data must be non-empty bytes")
        self.fake_data = bytes(fake_data)
        self.sch_fake_sent = False
        self.fake_sent = False
        self.ready = False  # set True by caller after successful connect
        self.t2a_event = asyncio.Event()
        self.t2a_msg = ""
        self.bypass_method = bypass_method
        self.peer_sock = peer_sock
        try:
            self.running_loop = asyncio.get_running_loop()
        except RuntimeError:
            self.running_loop = None
        logger.debug(f"Connection {self.id} initialized with bypass={bypass_method}")


class FakeTcpInjector(TcpInjector):
    def __init__(self, w_filter: str, connections: dict,
                 connections_lock: threading.Lock = None):
        super().__init__(w_filter)
        self.connections = connections
        self.lock = connections_lock or threading.Lock()
        logger.info("FakeTcpInjector started")

    # ------------- helpers -------------
    def _lookup(self, c_id):
        with self.lock:
            return self.connections.get(c_id)

    def _signal_close(self, connection: FakeInjectiveConnection, msg: str):
        connection.t2a_msg = msg
        if connection.running_loop is not None:
            try:
                connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)
            except RuntimeError:
                pass

    # ------------- threads -------------
    def fake_send_thread(self, packet: Packet, connection: FakeInjectiveConnection):
        """Inject fake data with a small delay so the ACK of the previous packet is in-flight."""
        time.sleep(0.002)
        with connection.thread_lock:
            if not connection.monitor or not connection.ready:
                return
            try:
                payload = connection.fake_data
                packet.tcp.psh = True
                # IP total length = header + TCP header + payload
                packet.ip.packet_len = packet.ip.packet_len + len(payload)
                packet.tcp.payload = payload

                if packet.ipv4:
                    packet.ipv4.ident = (packet.ipv4.ident + 1) & 0xffff

                if connection.bypass_method == "wrong_seq":
                    # Place seq BEFORE the real seq so DPI sees old data at the new position
                    packet.tcp.seq_num = (connection.syn_seq + 1 - len(payload)) & 0xffffffff
                    connection.fake_sent = True
                    self.w.send(packet, True)
                    logger.debug(f"Fake data injected for {connection.id}")
            except Exception:
                logger.exception(f"Error injecting fake data for {connection.id}")
                connection.monitor = False

    # ------------- close handler -------------
    def on_unexpected_packet(self, packet: Packet, connection: FakeInjectiveConnection, info_m: str):
        logger.warning(f"Unexpected packet for {connection.id}: {info_m}")
        connection.monitor = False
        try:
            connection.sock.close()
        except OSError:
            pass
        try:
            connection.peer_sock.close()
        except OSError:
            pass
        self._signal_close(connection, "unexpected_close")

    # ------------- inbound -------------
    def on_inbound_packet(self, packet: Packet, connection: FakeInjectiveConnection):
        if not connection.ready or connection.syn_seq == -1:
            self.on_unexpected_packet(packet, connection, "inbound before ready / no syn")
            return

        # SYN-ACK
        if packet.tcp.ack and packet.tcp.syn and (not packet.tcp.rst) and (not packet.tcp.fin) and \
                (len(packet.tcp.payload) == 0):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num

            if connection.syn_ack_seq != -1 and connection.syn_ack_seq != seq_num:
                self.on_unexpected_packet(packet, connection, "SYN-ACK seq mismatch")
                return
            if ack_num != ((connection.syn_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(packet, connection, "SYN-ACK ack mismatch")
                return

            connection.syn_ack_seq = seq_num
            self.w.send(packet, False)
            return

        # ACK after fake-data sent (handshake complete)
        if connection.fake_sent and packet.tcp.ack and (not packet.tcp.syn) and \
                (not packet.tcp.rst) and (not packet.tcp.fin) and \
                (len(packet.tcp.payload) == 0):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num

            if connection.syn_ack_seq == -1 or ((connection.syn_ack_seq + 1) & 0xffffffff) != seq_num:
                self.on_unexpected_packet(packet, connection, "ACK seq mismatch")
                return
            if ack_num != ((connection.syn_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(packet, connection, "ACK ack mismatch")
                return

            connection.monitor = False
            connection.t2a_msg = "fake_data_ack_recv"
            self._signal_close(connection, "fake_data_ack_recv")
            logger.info(f"Fake-data ACK received for {connection.id}; handshake complete.")
            return

        self.on_unexpected_packet(packet, connection, "unexpected inbound packet during handshake")

    # ------------- outbound -------------
    def on_outbound_packet(self, packet: Packet, connection: FakeInjectiveConnection):
        if connection.sch_fake_sent:
            self.on_unexpected_packet(packet, connection, "outbound after fake sent")
            return

        # SYN
        if packet.tcp.syn and (not packet.tcp.ack) and (not packet.tcp.rst) and \
                (not packet.tcp.fin) and (len(packet.tcp.payload) == 0):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if ack_num != 0:
                self.on_unexpected_packet(packet, connection, "SYN ack_num != 0")
                return
            if connection.syn_seq != -1 and connection.syn_seq != seq_num:
                self.on_unexpected_packet(packet, connection, "SYN seq mismatch")
                return
            connection.syn_seq = seq_num
            self.w.send(packet, False)
            return

        # Final ACK of 3WHS
        if packet.tcp.ack and (not packet.tcp.syn) and (not packet.tcp.rst) and \
                (not packet.tcp.fin) and (len(packet.tcp.payload) == 0):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if connection.syn_seq == -1 or ((connection.syn_seq + 1) & 0xffffffff) != seq_num:
                self.on_unexpected_packet(packet, connection, "ACK seq mismatch")
                return
            if connection.syn_ack_seq == -1 or ack_num != ((connection.syn_ack_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(packet, connection, "ACK ack mismatch")
                return

            self.w.send(packet, False)
            connection.sch_fake_sent = True
            threading.Thread(target=self.fake_send_thread,
                             args=(packet, connection), daemon=True).start()
            return

        self.on_unexpected_packet(packet, connection, "unexpected outbound packet")

    # ------------- main -------------
    def inject(self, packet: Packet):
        try:
            if packet.is_inbound:
                c_id = (packet.ip.dst_addr, packet.tcp.dst_port,
                        packet.ip.src_addr, packet.tcp.src_port)
                connection = self._lookup(c_id)
                if connection is None:
                    self.w.send(packet, False)
                    return
                with connection.thread_lock:
                    if not connection.monitor:
                        self.w.send(packet, False)
                        return
                    self.on_inbound_packet(packet, connection)
            elif packet.is_outbound:
                c_id = (packet.ip.src_addr, packet.tcp.src_port,
                        packet.ip.dst_addr, packet.tcp.dst_port)
                connection = self._lookup(c_id)
                if connection is None:
                    self.w.send(packet, False)
                    return
                with connection.thread_lock:
                    if not connection.monitor:
                        self.w.send(packet, False)
                        return
                    self.on_outbound_packet(packet, connection)
            else:
                logger.error("Impossible packet direction!")
        except Exception:
            # Never let the pydivert thread die
            logger.exception("Unhandled error in inject()")
            try:
                self.w.send(packet, False)
            except Exception:
                pass