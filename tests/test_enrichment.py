import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrichment import enrich, iocinfo


class EmbeddedEnrichmentTests(unittest.TestCase):
    def test_url_enrichment_uses_only_the_hostname(self):
        with (
            patch.object(iocinfo, "lookup_dns_full", return_value={"A Records": "192.0.2.1"}) as dns,
            patch.object(iocinfo, "lookup_rdap_domain", return_value={"Registrar": "Example"}) as rdap,
        ):
            result = enrich("https://example.com/private?token=sample", "URL")
        dns.assert_called_once_with("example.com")
        rdap.assert_called_once_with("example.com")
        self.assertEqual(result, {"DNS": {"A Records": "192.0.2.1"}, "WHOIS": {"Registrar": "Example"}})

    def test_ip_enrichment_keeps_evidence_grouped(self):
        with (
            patch.object(iocinfo, "lookup_ip_api", side_effect=AssertionError("Unencrypted lookup must not run")) as geo,
            patch.object(iocinfo, "lookup_ipinfo", return_value={"Hostname": "example.com"}) as info,
            patch.object(iocinfo, "lookup_rdap_ip", return_value={"Network": "TEST-NET-1"}) as rdap,
        ):
            result = enrich("192.0.2.1", "IP Address")
        geo.assert_not_called()
        for lookup in (info, rdap):
            lookup.assert_called_once_with("192.0.2.1")
        self.assertEqual(result["RDAP"]["Network"], "TEST-NET-1")
        self.assertEqual(result["IP information"]["Hostname"], "example.com")

    def test_hash_skips_ip_and_domain_enrichment(self):
        self.assertEqual(enrich("0" * 64, "Hash"), {})

