# Injector.py
import logging
import threading
from pydivert import WinDivert

logger = logging.getLogger(__name__)


class TcpInjector:
    def __init__(self, w_filter: str):
        self.w = WinDivert(w_filter)
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while self.running:
            try:
                packet = self.w.recv()
            except Exception as e:
                if self.running:
                    logger.exception(f"Injector recv error: {e}")
                continue
            try:
                self.inject(packet)
            except Exception:
                logger.exception("Unhandled error in inject()")

    def inject(self, packet):
        raise NotImplementedError

    def run(self):
        self.thread.join()

    def stop(self):
        self.running = False
        try:
            self.w.close()
        except Exception:
            pass