import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class TestConfigFile(unittest.TestCase):
    def test_config_is_valid_json_object(self):
        config = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))

        self.assertIsInstance(config, dict)

        for key in ("LISTEN_HOST", "LISTEN_PORT", "CONNECT_IP", "CONNECT_PORT"):
            self.assertIn(key, config)

    def test_config_ports_are_in_range(self):
        config = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))

        for key in ("LISTEN_PORT", "CONNECT_PORT"):
            self.assertIsInstance(config[key], int)
            self.assertGreaterEqual(config[key], 1)
            self.assertLessEqual(config[key], 65535)

    def test_config_sni_list_is_non_empty(self):
        config = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))

        self.assertIsInstance(config["SNI_LIST"], list)
        self.assertTrue(config["SNI_LIST"])
        self.assertTrue(all(isinstance(value, str) and value for value in config["SNI_LIST"]))


if __name__ == "__main__":
    unittest.main()
