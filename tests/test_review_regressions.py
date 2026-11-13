"""Regression tests for the second review, with no live provider calls."""
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import credentials
import main


class ReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = main.QApplication.instance() or main.QApplication([])

    def setUp(self):
        self.window = main.Win()
        self.addCleanup(self.window.close)

    def assess(self, vt, tf, uh, kind="Domain", evidence=None):
        self.window.done("example.com", "example.com", kind, evidence or {}, 0,
                         {"status": vt}, {"status": tf}, {"status": uh}, {})
        return self.window.assessment_text.text()

    def test_incomplete_coverage_and_confirmed_match(self):
        for tf, expected, count in (
            ("Source error", "Insufficient data", 0),
            ("No match", "Partial coverage", 1),
            ("IOC FOUND", "THREAT INTELLIGENCE FOUND", 1),
        ):
            with self.subTest(tf=tf):
                text = self.assess("Not configured", tf, "Rate limit reached")
                self.assertIn(expected, text)
                self.assertIn(f"{count} of 3", text)

    def test_no_detections_with_full_or_partial_coverage(self):
        vt = {"status": "Available", "malicious": 0, "suspicious": 0,
              "harmless": 1, "undetected": 0}
        for kind, value, source_status, headline, coverage in (
            ("Domain", "example.com", "No match", "NO THREAT INTELLIGENCE FOUND", 3),
            ("Hash", "a" * 40, "Unsupported hash type", "Partial coverage", 1),
        ):
            with self.subTest(kind=kind), patch.object(main, "RelatedWorker"):
                source = {"status": source_status}
                self.window.done(value, value, kind, {}, 0, vt, source, source, {})
                assessment = self.window.assessment_text.text()
                self.assertIn(headline, assessment)
                self.assertIn(f"{coverage} of 3", assessment)

    def test_vt_zero_vendor_counts_are_no_data(self):
        stats = dict.fromkeys(("malicious", "suspicious", "harmless", "undetected"), 0)
        response = MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(
            {"data": {"attributes": {"last_analysis_stats": stats}}}
        ).encode()
        with (
            patch.object(main, "vt_api_key", return_value="test-key"),
            patch.object(main, "tls_context"),
            patch.object(main.urllib.request, "urlopen", return_value=response),
            patch.object(main, "RelatedWorker") as worker,
        ):
            vt = main.vt_lookup("Domain", "example.com")
            self.assertEqual(vt["status"], "No data")
            self.assertIn("Insufficient data", self.assess(vt["status"], "Source error", "Source error"))
            worker.assert_not_called()

    def test_vt_404_uses_tls_and_skips_relationships(self):
        error = urllib.error.HTTPError("https://example.com", 404, "Not found", {}, None)
        with (
            patch.object(main, "vt_api_key", return_value="test-key"),
            patch.object(main, "tls_context") as context,
            patch.object(main.urllib.request, "urlopen", side_effect=error) as request,
            patch.object(main, "RelatedWorker") as worker,
        ):
            result = main.vt_lookup("Domain", "example.com")
            self.assertEqual(result["status"], "No existing report")
            self.assertIs(request.call_args.kwargs["context"], context.return_value)
            self.assess(result["status"], "No match", "No match")
            worker.assert_not_called()

    def test_sha1_skips_abusech_requests(self):
        with patch.object(main, "abusech_api_key") as key:
            for lookup in (main.threatfox_lookup, main.urlhaus_lookup):
                self.assertEqual(lookup("Hash", "a" * 40)["status"], "Unsupported hash type")
            key.assert_not_called()

    def test_known_legacy_placeholders(self):
        cases = (
            ("virustotal", "api_key", "paste_your_virustotal_api_key_here"),
            ("virustotal", "api_key", "YOUR_VIRUSTOTAL_API_KEY"),
            ("abusech", "auth_key", "Your_Abusech_Auth_Key"),
        )
        with tempfile.TemporaryDirectory() as temp, patch.object(credentials, "_stored", return_value=""):
            for provider, field, value in cases:
                with self.subTest(provider=provider, value=value):
                    (Path(temp) / f"{provider}.json").write_text(json.dumps({field: value}), encoding="utf-8")
                    result = credentials.resolve(provider, environ={}, config_dir=temp)
                    self.assertEqual((result.value, result.source), ("", "Not configured"))

    def test_ip_summary_shows_asn_from_ipinfo(self):
        self.assess("Not configured", "Not configured", "Not configured", "IP Address",
                    {"IP information": {"Org/ASN": "AS15169 Google LLC"}})
        self.assertIn("ASN: AS15169", self.window.id.b.text())
        self.assertIn("Organization: Google LLC", self.window.id.b.text())
