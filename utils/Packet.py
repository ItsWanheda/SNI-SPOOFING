# Packet.py
import struct
import logging

logger = logging.getLogger(__name__)


def _require_len(name: str, value: bytes, expected: int):
    if not isinstance(value, (bytes, bytearray)) or len(value) != expected:
        raise ValueError(f"{name} must be exactly {expected} bytes, got "
                         f"{len(value) if hasattr(value, '__len__') else 'N/A'}")


class ClientHelloMaker:
    tls_ch_template_str = (
        "1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b9375b"
        "b48d34f2b20bf018bcc90a7c89a230094815ad0c15b736e38c01209d72d282cb5e2105328150024"
        "130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b006700ff0100018f"
        "0000000b00090000066d63692e6972000b000403000102000a00160014001d0017001e0019001801"
        "000101010201030104002300000010000e000c02683208687474702f312e31001600000017000000"
        "0d002a0028040305030603080708080809080a080b08040805080604010501060103030301030204"
        "0205020602002b00050403040303002d00020101003300260024001d0020435bacc4d05f9d41fef4"
        "4ab3ad55616c36e0613473e2338770efdaa98693d217001500d50000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000"
    )
    tls_ch_template = bytes.fromhex(tls_ch_template_str)
    template_sni = b"#"  # placeholder, never embedded in output
    static1 = tls_ch_template[:11]
    static2 = b"\x20"
    static3 = tls_ch_template[76:120]
    static4 = tls_ch_template[127 + len(template_sni):262 + len(template_sni)]
    static5 = b"\x00\x15"

    tls_change_cipher = b"\x14\x03\x03\x00\x01\x01"
    tls_app_data_header = b"\x17\x03\x03"

    @classmethod
    def get_client_hello_with(cls, rnd: bytes, sess_id: bytes, target_sni: bytes,
                              key_share: bytes) -> bytes:
        if not isinstance(target_sni, (bytes, bytearray)):
            raise TypeError("target_sni must be bytes")
        if len(target_sni) == 0 or len(target_sni) > 255:
            raise ValueError("target_sni length must be 1..255")
        _require_len("rnd", rnd, 32)
        _require_len("sess_id", sess_id, 32)
        _require_len("key_share", key_share, 32)

        server_name_ext = (
            struct.pack("!H", len(target_sni) + 5)
            + struct.pack("!H", len(target_sni) + 3)
            + b"\x00"
            + struct.pack("!H", len(target_sni))
            + bytes(target_sni)
        )
        padding_len = 219 - len(target_sni)
        if padding_len < 0:
            raise ValueError("target_sni too long for padding slot")
        padding_ext = struct.pack("!H", padding_len) + (b"\x00" * padding_len)
        return (
            cls.static1 + rnd + cls.static2 + sess_id + cls.static3
            + server_name_ext + cls.static4 + key_share
            + cls.static5 + padding_ext
        )

    @classmethod
    def parse_client_hello(cls, client_hello_bytes: bytes):
        if len(client_hello_bytes) != 517:
            raise ValueError(f"unexpected ClientHello length {len(client_hello_bytes)}")
        rnd = client_hello_bytes[11:43]
        sess_id = client_hello_bytes[44:76]
        sni_len = struct.unpack("!H", client_hello_bytes[125:127])
        tls_sni = client_hello_bytes[127:127 + sni_len].decode("ascii", errors="replace")
        ks_ind = 262 + len(tls_sni)
        key_share = client_hello_bytes[ks_ind:ks_ind + 32]
        rebuilt = cls.get_client_hello_with(rnd, sess_id, tls_sni.encode("ascii"), key_share)
        assert rebuilt == client_hello_bytes, "ClientHello parse/rebuild mismatch"
        return rnd, sess_id, tls_sni, key_share

    @classmethod
    def get_client_response_with(cls, app_data1: bytes):
        if not isinstance(app_data1, (bytes, bytearray)):
            raise TypeError("app_data1 must be bytes")
        return (cls.tls_change_cipher
                + cls.tls_app_data_header
                + struct.pack("!H", len(app_data1))
                + bytes(app_data1))

    @classmethod
    def parse_client_response(cls, client_response_bytes: bytes):
        if len(client_response_bytes) < 32:
            raise ValueError("response too short")
        app_data1 = client_response_bytes[11:]
        rebuilt = cls.get_client_response_with(app_data1)
        assert rebuilt == client_response_bytes, "response parse/rebuild mismatch"
        return app_data1


class ServerHelloMaker:
    tls_sh_template_str = (
        "160303007a0200007603035e39ed63ad58140fbd12af1c6a37c879299a39461b308d63cb1dae291c"
        "5b69702057d2a640c5ca53fed0f24491baaf96347f12db603fd1babe6bc3ad0b6fbde40613020000"
        "2e002b0002030400330024001d0020d934ed49a1619be820856c4986e865c5b0e4eb188ebd30193"
        "271e8171152eb4e"
    )
    tls_sh_template = bytes.fromhex(tls_sh_template_str)
    static1 = tls_sh_template[:11]
    static2 = b"\x20"
    static3 = tls_sh_template[76:95]
    tls_change_cipher = b"\x14\x03\x03\x00\x01\x01"
    tls_app_data_header = b"\x17\x03\x03"

    @classmethod
    def get_server_hello_with(cls, rnd: bytes, sess_id: bytes, key_share: bytes,
                              app_data1: bytes):
        _require_len("rnd", rnd, 32)
        _require_len("sess_id", sess_id, 32)
        _require_len("key_share", key_share, 32)
        if not isinstance(app_data1, (bytes, bytearray)):
            raise TypeError("app_data1 must be bytes")
        return (cls.static1 + rnd + cls.static2 + sess_id + cls.static3 + key_share
                + cls.tls_change_cipher + cls.tls_app_data_header
                + struct.pack("!H", len(app_data1)) + bytes(app_data1))

    @classmethod
    def parse_server_hello(cls, server_hello_bytes: bytes):
        if len(server_hello_bytes) < 159:
            raise ValueError("server hello too short")
        rnd = server_hello_bytes[11:43]
        sess_id = server_hello_bytes[44:76]
        key_share = server_hello_bytes[95:127]
        app_data1 = server_hello_bytes[138:]
        rebuilt = cls.get_server_hello_with(rnd, sess_id, key_share, app_data1)
        assert rebuilt == server_hello_bytes, "server hello parse/rebuild mismatch"
        return rnd, sess_id, key_share, app_data1