import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import credentials


class CredentialTests(unittest.TestCase):
    def test_environment_wins(self):
        with patch.object(credentials, "_stored", return_value="secure"):
            result = credentials.resolve("virustotal", environ={"VT_API_KEY": " env "})
        self.assertEqual((result.value, result.source), ("env", "Environment"))

    def test_store_wins_over_json(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "virustotal.json").write_text('{"api_key":"legacy"}')
            with patch.object(credentials, "_stored", return_value="secure"):
                result = credentials.resolve("virustotal", environ={}, config_dir=d)
            self.assertEqual((result.value, result.source), ("secure", "Windows Credential Manager"))

    def test_json_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "abusech.json").write_text('{"auth_key":"legacy"}')
            with patch.object(credentials, "_stored", return_value=""):
                result = credentials.resolve("abusech", environ={}, config_dir=d)
            self.assertEqual((result.value, result.source), ("legacy", "Legacy JSON"))

    def test_unconfigured(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(credentials, "_stored", return_value=""):
                result = credentials.resolve("virustotal", environ={}, config_dir=d)
            self.assertEqual(result.source, "Not configured")

    def test_store_failure_does_not_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "virustotal.json").write_text('{"api_key":"legacy"}')
            with patch.object(credentials, "_stored", side_effect=credentials.CredentialStoreError("failure")):
                with self.assertRaises(credentials.CredentialStoreError):
                    credentials.resolve("virustotal", environ={}, config_dir=d)

    def test_save_does_not_write_json(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "virustotal.json"
            path.write_text('{"api_key":"legacy"}')
            class FakeKeyring:
                def set_password(self, service, user, value):
                    self.saved = (service, user, value)
            backend = FakeKeyring()
            with patch.object(credentials, "_backend", return_value=backend):
                credentials.save("virustotal", " new ")
            self.assertEqual(backend.saved, (credentials.SERVICE, "virustotal", "new"))
            self.assertEqual(path.read_text(), '{"api_key":"legacy"}')

    def test_empty_save_rejected(self):
        with self.assertRaises(ValueError):
            credentials.save("virustotal", "  ")

    def test_unknown_provider(self):
        with self.assertRaises(ValueError):
            credentials.resolve("invalid", environ={})

    def test_no_secrets_in_store_errors(self):
        class BadKeyring:
            def set_password(self, *args):
                raise RuntimeError("secret=topsecret")
        with patch.object(credentials, "_backend", return_value=BadKeyring()):
            with self.assertRaises(credentials.CredentialStoreError) as ctx:
                credentials.save("virustotal", "topsecret")
        self.assertNotIn("topsecret", str(ctx.exception))



    def test_save_rejects_non_string_values(self):
        for value in (None, 123, ["key"], {"key": "value"}):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(ValueError):
                    credentials.save("virustotal", value)

    def test_environment_rejects_non_string_values(self):
        for value in (123, ["key"], {"key": "value"}):
            with self.subTest(value_type=type(value).__name__):
                with patch.object(credentials, "_stored", return_value=""):
                    with self.assertRaises(ValueError):
                        credentials.resolve(
                            "virustotal",
                            environ={"VT_API_KEY": value}
                        )

    def test_legacy_json_rejects_non_string_values(self):
        import json

        for value in (123, ["key"], {"key": "value"}):
            with self.subTest(value_type=type(value).__name__):
                with tempfile.TemporaryDirectory() as d:
                    path = Path(d) / "virustotal.json"
                    path.write_text(
                        json.dumps({"api_key": value}),
                        encoding="utf-8"
                    )
                    with patch.object(credentials, "_stored", return_value=""):
                        result = credentials.resolve(
                            "virustotal", environ={}, config_dir=d
                        )
                    self.assertEqual(result.source, "Not configured")

    def test_secure_store_rejects_non_string_values(self):
        class InvalidKeyring:
            def get_password(self, service, provider):
                return {"unexpected": "object"}

        with patch.object(credentials, "_backend", return_value=InvalidKeyring()):
            with self.assertRaises(credentials.CredentialStoreError):
                credentials.stored("virustotal")

if __name__ == "__main__":
    unittest.main()
