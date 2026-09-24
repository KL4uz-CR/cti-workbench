import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from core import normalize_ioc


class NormalizeIOCTests(unittest.TestCase):
    def test_ipv4(self):
        self.assertEqual(normalize_ioc("8.8.8.8")[1:], ("8.8.8.8", "IP Address"))

    def test_rejects_invalid_ipv4(self):
        self.assertEqual(normalize_ioc("999.999.999.999")[2], "Unknown")

    def test_ipv4_port(self):
        self.assertEqual(normalize_ioc("8.8.8.8:53")[1:], ("8.8.8.8", "IP Address"))

    def test_rejects_invalid_port(self):
        self.assertEqual(normalize_ioc("8.8.8.8:99999")[2], "Unknown")

    def test_ipv6(self):
        self.assertEqual(normalize_ioc("2001:4860:4860::8888")[2], "IP Address")

    def test_ipv6_port(self):
        self.assertEqual(normalize_ioc("[2001:4860:4860::8888]:443")[1:], ("2001:4860:4860::8888", "IP Address"))

    def test_domain_normalization(self):
        self.assertEqual(normalize_ioc("Example.COM/")[1:], ("example.com", "Domain"))

    def test_url_normalization(self):
        self.assertEqual(normalize_ioc("HTTPS://Example.COM/a?x=1")[1:], ("https://example.com/a?x=1", "URL"))

    def test_hash_normalization(self):
        value="A"*64
        self.assertEqual(normalize_ioc(value)[1:], (value.lower(), "Hash"))


if __name__ == "__main__":
    unittest.main()
