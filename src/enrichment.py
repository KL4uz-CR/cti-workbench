"""Run the embedded iocinfo enrichment functions without its CLI or settings."""
from urllib.parse import urlsplit

from iocinfo import main as iocinfo


def enrich(value: str, kind: str) -> dict:
    """Return the upstream fields grouped by lookup.

    CTI Workbench handles authenticated sources through its own clients.
    URL enrichment sends only the hostname to DNS and RDAP.
    """
    if kind in ("Domain", "URL"):
        host = urlsplit(value).hostname if kind == "URL" else value
        return {
            "DNS": iocinfo.lookup_dns_full(host),
            "WHOIS": iocinfo.lookup_rdap_domain(host),
        }
    if kind == "IP Address":
        return {
            "IP information": iocinfo.lookup_ipinfo(value),
            "RDAP": iocinfo.lookup_rdap_ip(value),
        }
    return {}
