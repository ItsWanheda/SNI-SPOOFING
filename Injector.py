# Injector.py
import threading
from pydivert import PyDivert

class TcpInjector:
    def __init__(self, w_filter):
        self.w = PyDivert(w_filter)
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while self.running:
            try:
                packet = self.w.recv()
                self.inject(packet)
            except Exception as e:
                if self.running:
                    print(f"Injector error: {e}")

    def inject(self, packet):
        raise NotImplementedError

    def run(self):
        self.thread.join()