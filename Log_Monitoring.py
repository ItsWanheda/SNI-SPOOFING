# Log_Monitoring.py
import uuid
import threading

class MonitorConnection:
    def __init__(self, sock, src_ip, dst_ip, src_port, dst_port):
        self.id = (src_ip, src_port, dst_ip, dst_port)
        self.sock = sock
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.syn_seq = -1
        self.syn_ack_seq = -1
        self.monitor = True
        self.thread_lock = threading.Lock()