"""Credential resolution for CTI Workbench; no secrets are logged."""
from __future__ import annotations
import sys

import json
import os
from dataclasses import dataclass
from pathlib import Path

SERVICE = "CTI Workbench"
ROOT = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent.parent
LEGACY_PLACEHOLDERS = {
    "PASTE_YOUR_VIRUSTOTAL_API_KEY_HERE",
    "YOUR_VIRUSTOTAL_API_KEY",
    "YOUR_ABUSECH_AUTH_KEY",
}
PROVIDERS = {
    "virustotal": ("VT_API_KEY", "virustotal.json", "api_key"),
    "abusech": ("ABUSECH_AUTH_KEY", "abusech.json", "auth_key"),
}


class CredentialStoreError(RuntimeError):
    """Secure store is unavailable or returned an error."""


@dataclass(frozen=True)
class Credential:
    value: str
    source: str


def _provider(provider):
    if provider not in PROVIDERS:
        raise ValueError("Unknown credential provider")
    return PROVIDERS[provider]


def _backend():
    try:
        import keyring
        from keyring.backends.Windows import WinVaultKeyring
        backend = keyring.get_keyring()
        if not isinstance(backend, WinVaultKeyring):
            raise CredentialStoreError("Windows Credential Manager backend is not active")
        return keyring
    except CredentialStoreError:
        raise
    except Exception:
        raise CredentialStoreError("Windows Credential Manager is unavailable") from None


def _stored(provider):
    keyring = _backend()
    try:
        return (keyring.get_password(SERVICE, provider) or "").strip()
    except Exception:
        raise CredentialStoreError("Cannot read Windows Credential Manager") from None


def resolve(provider, *, environ=None, config_dir=None):
    env, filename, field = _provider(provider)
    variables = os.environ if environ is None else environ
    raw = variables.get(env)
    if raw is not None and not isinstance(raw, str):
        raise ValueError("Credential environment value must be text")
    value = (raw or "").strip()
    if value:
        return Credential(value, "Environment")
    # Fail closed if the secure store cannot be checked reliably.
    value = _stored(provider)
    if value:
        return Credential(value, "Windows Credential Manager")
    directory = ROOT / "config" if config_dir is None else Path(config_dir)
    path = directory / filename
    try:
        if path.is_file():
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                raw = data.get(field)
                value = raw.strip() if isinstance(raw, str) else ""
                if value and value.upper() not in LEGACY_PLACEHOLDERS:
                    return Credential(value, "Legacy JSON")
    except (OSError, ValueError, TypeError):
        # Legacy configuration is optional; never reveal its contents.
        pass
    return Credential("", "Not configured")


def save(provider, value):
    _provider(provider)
    if not isinstance(value, str):
        raise ValueError("Credential must be text")
    value = value.strip()
    if not value:
        raise ValueError("Cannot save an empty credential")
    keyring = _backend()
    try:
        keyring.set_password(SERVICE, provider, value)
    except Exception:
        raise CredentialStoreError("Cannot save to Windows Credential Manager") from None


def delete(provider):
    _provider(provider)
    keyring = _backend()
    try:
        keyring.delete_password(SERVICE, provider)
    except keyring.errors.PasswordDeleteError:
        return False
    except Exception:
        raise CredentialStoreError("Cannot delete from Windows Credential Manager") from None
    return True


def stored(provider):
    _provider(provider)
    return bool(_stored(provider))
