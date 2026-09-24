import unittest

from utils.Packet import ClientHelloMaker, ServerHelloMaker


class TestClientHelloMaker(unittest.TestCase):
    def setUp(self):
        self.rnd = bytes(range(32))
        self.session_id = bytes(range(32, 64))
        self.key_share = bytes(range(64, 96))

    def test_client_hello_round_trip(self):
        sni = b"example.com"
        packet = ClientHelloMaker.get_client_hello_with(
            self.rnd, self.session_id, sni, self.key_share
        )

        self.assertEqual(len(packet), 517)

        parsed = ClientHelloMaker.parse_client_hello(packet)
        self.assertEqual(parsed, (self.rnd, self.session_id, "example.com", self.key_share))

    def test_client_hello_rejects_invalid_fields(self):
        with self.assertRaises(ValueError):
            ClientHelloMaker.get_client_hello_with(
                b"short", self.session_id, b"example.com", self.key_share
            )

        with self.assertRaises(ValueError):
            ClientHelloMaker.get_client_hello_with(
                self.rnd, self.session_id, b"", self.key_share
            )

        with self.assertRaises(ValueError):
            ClientHelloMaker.get_client_hello_with(
                self.rnd, self.session_id, b"a" * 256, self.key_share
            )

    def test_client_response_round_trip(self):
        app_data = b"test application data"
        response = ClientHelloMaker.get_client_response_with(app_data)

        self.assertEqual(
            ClientHelloMaker.parse_client_response(response),
            app_data,
        )

    def test_client_response_rejects_short_input(self):
        with self.assertRaises(ValueError):
            ClientHelloMaker.parse_client_response(b"too short")


class TestServerHelloMaker(unittest.TestCase):
    def test_server_hello_round_trip(self):
        rnd = bytes(range(32))
        session_id = bytes(range(32, 64))
        key_share = bytes(range(64, 96))
        app_data = b"server application data"

        packet = ServerHelloMaker.get_server_hello_with(
            rnd, session_id, key_share, app_data
        )

        parsed = ServerHelloMaker.parse_server_hello(packet)

        self.assertEqual(parsed, (rnd, session_id, key_share, app_data))

    def test_server_hello_rejects_short_input(self):
        with self.assertRaises(ValueError):
            ServerHelloMaker.parse_server_hello(b"short")


if __name__ == "__main__":
    unittest.main()
