"""Core helpers for CTI Workbench.

This module intentionally contains no Qt code so IOC normalization, TLS setup,
and diagnostics can be tested independently from the desktop UI.
"""
from __future__ import annotations

import ipaddress
import logging
from logging.handlers import RotatingFileHandler
import re
import ssl
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

APP_NAME = "CTI Workbench"
APP_VERSION = "0.5.7"
ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT / "logs"
LOG_FILE = LOG_DIR / "cti-workbench.log"


def get_logger(name: str = "cti_workbench") -> logging.Logger:
    """Return the application logger, configured once with local rotation."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    logger.propagate = False
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        logger.addHandler(handler)
    except OSError:
        logger.addHandler(logging.NullHandler())
    return logger


logger = get_logger()


def _ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def normalize_ioc(value: str):
    """Return (original, normalized, type) using strict standard-library IP validation."""
    original = value.strip()
    v = original
    if not v:
        return original, original, "Unknown"

    if re.match(r"^https?://", v, re.I):
        try:
            u = urlsplit(v)
            host = (u.hostname or "").lower().rstrip(".")
            if not host:
                return original, original, "Unknown"
            # Validate explicit port access; urlsplit raises ValueError for invalid ports.
            port_num = u.port
            if port_num is not None and not (0 <= port_num <= 65535):
                return original, original, "Unknown"
            host_for_url = f"[{host}]" if ":" in host else host
            port = f":{port_num}" if port_num is not None else ""
            normalized = urlunsplit((u.scheme.lower(), host_for_url + port, u.path, u.query, u.fragment))
            return original, normalized, "URL"
        except (ValueError, UnicodeError):
            return original, original, "Unknown"

    # Bracketed IPv6:port (unambiguous form).
    m = re.fullmatch(r"\[([^\]]+)\]:(\d{1,5})", v)
    if m:
        addr, port = _ip(m.group(1)), int(m.group(2))
        if addr is not None and addr.version == 6 and port <= 65535:
            return original, addr.compressed, "IP Address"
        return original, original, "Unknown"

    # IPv4:port.
    m = re.fullmatch(r"([^:]+):(\d{1,5})", v)
    if m:
        addr, port = _ip(m.group(1)), int(m.group(2))
        if addr is not None and addr.version == 4 and port <= 65535:
            return original, addr.compressed, "IP Address"

    # Bare IPv4/IPv6.
    addr = _ip(v)
    if addr is not None:
        return original, addr.compressed, "IP Address"

    candidate = v.rstrip("/.").lower()
    if re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", candidate, re.I):
        return original, candidate, "Domain"

    if re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", v):
        return original, v.lower(), "Hash"
    return original, original, "Unknown"


def safe_dict(value):
    return value if isinstance(value, dict) else {}


def tls_context():
    """Build a verified TLS context and record which trust store was selected."""
    try:
        import certifi
        cafile = certifi.where()
        ctx = ssl.create_default_context(cafile=cafile)
        logger.debug("TLS trust store: %s", cafile)
        return ctx
    except Exception as exc:
        logger.warning("certifi trust store unavailable; using platform defaults: %s", exc)
        return ssl.create_default_context()
