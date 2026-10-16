"""Regression tests for CTI source responses. No external API calls."""
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import main


class ThreatFoxTests(unittest.TestCase):

    def lookup(self, payload):
        with patch.object(main, "abusech_api_key", return_value="TEST-ONLY"):
            with patch.object(main, "post_json", return_value=payload):
                return main.threatfox_lookup("Domain", "example.com")

    def test_no_result(self):
        result = self.lookup({"query_status": "no_result", "data": []})
        self.assertEqual(result["status"], "No match")

    def test_authentication_error_not_no_match(self):
        result = self.lookup({
            "query_status": "invalid_auth_key",
            "data": []
        })
        self.assertEqual(result["status"], "Source error")

    def test_valid_match(self):
        result = self.lookup({
            "query_status": "ok",
            "data": [{
                "ioc": "example.com",
                "malware": "Test malware",
                "threat_type": "Test threat"
            }]
        })
        self.assertEqual(result["status"], "IOC FOUND")
        self.assertEqual(result["count"], 1)

    def test_invalid_data_structure(self):
        result = self.lookup({
            "query_status": "ok",
            "data": {"unexpected": "object"}
        })
        self.assertEqual(result["status"], "Source error")

    def test_http_429(self):
        error = urllib.error.HTTPError(
            "https://threatfox-api.abuse.ch/api/v1/",
            429, "Too Many Requests", {}, None
        )
        with patch.object(main, "abusech_api_key", return_value="TEST-ONLY"):
            with patch.object(main, "post_json", side_effect=error):
                result = main.threatfox_lookup("Domain", "example.com")
        self.assertEqual(result["status"], "Rate limit reached")



class URLhausTests(unittest.TestCase):

    def lookup(self, payload, ioc_type="Domain", value="example.com"):
        with patch.object(main, "abusech_api_key", return_value="TEST-ONLY"):
            with patch.object(main, "post_form_json", return_value=payload):
                return main.urlhaus_lookup(ioc_type, value)

    def test_no_result(self):
        result = self.lookup({"query_status": "no_results"})
        self.assertEqual(result["status"], "No match")

    def test_authentication_error(self):
        result = self.lookup({"query_status": "invalid_auth_key"})
        self.assertEqual(result["status"], "Source error")

    def test_valid_host_match(self):
        result = self.lookup({
            "query_status": "ok",
            "urls": [{
                "url": "https://example.com/test",
                "url_status": "online",
                "threat": "malware_download"
            }]
        })
        self.assertEqual(result["status"], "IOC FOUND")
        self.assertEqual(result["count"], 1)

    def test_invalid_urls_structure(self):
        result = self.lookup({
            "query_status": "ok",
            "urls": ["invalid"]
        })
        self.assertEqual(result["status"], "Source error")

    def test_empty_host_results(self):
        result = self.lookup({
            "query_status": "ok",
            "urls": []
        })
        self.assertNotEqual(result["status"], "IOC FOUND")

    def test_valid_url_match(self):
        result = self.lookup({
            "query_status": "ok",
            "url": "https://example.com/test",
            "url_status": "online"
        }, "URL", "https://example.com/test")
        self.assertEqual(result["status"], "IOC FOUND")

    def test_http_429(self):
        error = urllib.error.HTTPError(
            "https://urlhaus-api.abuse.ch/v1/host/",
            429, "Too Many Requests", {}, None
        )
        with patch.object(main, "abusech_api_key", return_value="TEST-ONLY"):
            with patch.object(main, "post_form_json", side_effect=error):
                result = main.urlhaus_lookup("Domain", "example.com")
        self.assertEqual(result["status"], "Rate limit reached")


    def test_valid_sha256_hash(self):
        sha256 = "a" * 64
        result = self.lookup({
            "query_status": "ok",
            "sha256_hash": sha256,
            "file_type": "exe",
            "signature": "Example Malware"
        }, "Hash", sha256)
        self.assertEqual(result["status"], "IOC FOUND")

    def test_valid_md5_hash(self):
        md5 = "b" * 32
        result = self.lookup({
            "query_status": "ok",
            "md5_hash": md5,
            "file_type": "exe"
        }, "Hash", md5)
        self.assertEqual(result["status"], "IOC FOUND")

    def test_empty_hash_response(self):
        result = self.lookup({
            "query_status": "ok"
        }, "Hash", "a" * 64)
        self.assertNotEqual(result["status"], "IOC FOUND")

    def test_invalid_hash_response(self):
        result = self.lookup({
            "query_status": "ok",
            "sha256_hash": None,
            "md5_hash": None
        }, "Hash", "a" * 64)
        self.assertEqual(result["status"], "Source error")

if __name__ == "__main__":
    unittest.main()
