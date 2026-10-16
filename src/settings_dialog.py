"""Manual credential settings; no existing secrets are displayed in fields."""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel, QLineEdit,
    QPushButton, QMessageBox, QWidget,
)

from core import APP_VERSION, tls_context
from credentials import CredentialStoreError, resolve, save, delete


class ConnectionWorker(QThread):
    finished_test = Signal(str, str)

    def __init__(self, provider, key):
        super().__init__()
        self.provider = provider
        self.key = key

    def run(self):
        try:
            if self.provider == "virustotal":
                req = urllib.request.Request(
                    "https://www.virustotal.com/api/v3/domains/example.com",
                    headers={"x-apikey": self.key, "Accept": "application/json",
                             "User-Agent": f"CTI-Workbench/{APP_VERSION}"},
                )
                with urllib.request.urlopen(req, timeout=15, context=tls_context()) as response:
                    response.read(1024)
            else:
                # A benign, fixed IOC lookup tests ThreatFox authentication without
                # uploading user data or running an IOC scan.
                body = json.dumps({"query": "search_ioc", "search_term": "example.com", "exact_match": True}).encode()
                req = urllib.request.Request(
                    "https://threatfox-api.abuse.ch/api/v1/", data=body,
                    headers={"Auth-Key": self.key, "Content-Type": "application/json",
                             "Accept": "application/json", "User-Agent": f"CTI-Workbench/{APP_VERSION}"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=15, context=tls_context()) as response:
                    payload = json.loads(response.read(32768).decode("utf-8"))
                if str(payload.get("query_status", "")).lower() in ("invalid_auth_key", "unauthorized", "authentication_error"):
                    self.finished_test.emit(self.provider, "Authentication rejected")
                    return
            self.finished_test.emit(self.provider, "Connection successful (sample lookup)")
        except urllib.error.HTTPError as error:
            if error.code in (401, 403):
                status = "Authentication or permission rejected"
            elif error.code == 429:
                status = "Rate limit reached"
            else:
                status = f"HTTP {error.code}"
            self.finished_test.emit(self.provider, status)
        except Exception:
            self.finished_test.emit(self.provider, "Connection unavailable (network or service error)")
        finally:
            self.key = ""


class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings — CTI Workbench")
        self.setMinimumWidth(510)
        self._workers = {}
        self._test_revisions = {}
        self._controls = {}
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("API credentials are stored in Windows Credential Manager."))
        layout.addWidget(QLabel("Existing credentials are never shown or changed automatically."))
        for provider, title in (("virustotal", "VirusTotal"), ("abusech", "abuse.ch (ThreatFox / URLhaus)")):
            group = QGroupBox(title)
            form = QVBoxLayout(group)
            source = QLabel("Credential source: checking...")
            form.addWidget(source)
            entry_row = QHBoxLayout()
            field = QLineEdit()
            field.setEchoMode(QLineEdit.Password)
            field.setPlaceholderText("Enter a new key (leave blank to keep current)")
            entry_row.addWidget(field)
            show = QPushButton("Show")
            show.setCheckable(True)
            show.toggled.connect(lambda checked, f=field, b=show: self._toggle(f, b, checked))
            entry_row.addWidget(show)
            form.addLayout(entry_row)
            buttons = QHBoxLayout()
            test = QPushButton("Test Connection")
            store = QPushButton("Save")
            remove = QPushButton("Remove")
            test.setObjectName("testButton")
            store.setObjectName("saveButton")
            remove.setObjectName("removeButton")
            store.setStyleSheet(
                "QPushButton#saveButton{background:#145C55;color:#FFFFFF;"
                "border:1px solid #1D8A7B;font-weight:750}"
                "QPushButton#saveButton:hover{background:#187468}"
            )
            remove.setToolTip("Remove the stored credential")
            remove.setStyleSheet(
                "QPushButton#removeButton{background:#3B2D20;color:#F6C98B;"
                "border:1px solid #80603A;font-weight:600}"
                "QPushButton#removeButton:hover{background:#513A25;"
                "border-color:#B78A50}"
            )
            for button in (test, store, remove):
                buttons.addWidget(button)
            form.addLayout(buttons)
            status = QLabel("Not tested")
            form.addWidget(status)
            self._controls[provider] = (source, field, test, store, remove, status)
            field.textChanged.connect(
                lambda _text, p=provider: self._invalidate_test(p)
            )
            test.clicked.connect(lambda checked=False, p=provider: self._test(p))
            store.clicked.connect(lambda checked=False, p=provider: self._save(p))
            remove.clicked.connect(lambda checked=False, p=provider: self._remove(p))
            layout.addWidget(group)
        close = QPushButton("Close")
        close.clicked.connect(self.close)
        layout.addWidget(close)
        self._refresh_all()

    @staticmethod
    def _toggle(field, button, checked):
        field.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)
        button.setText("Hide" if checked else "Show")

    def _invalidate_test(self, provider):
        self._test_revisions[provider] = self._test_revisions.get(provider, 0) + 1
        self._controls[provider][5].setText("Not tested")

    def _refresh_all(self):
        for provider in self._controls:
            self._refresh(provider)

    def _refresh(self, provider):
        label = self._controls[provider][0]
        try:
            credential = resolve(provider)
            label.setText("Credential source: " + credential.source)
        except CredentialStoreError:
            label.setText("Windows Credential Manager unavailable. Check its availability and try again.")

    def _save(self, provider):
        source, field, *_ = self._controls[provider]
        value = field.text().strip()
        if not value:
            QMessageBox.information(self, "No changes", "Enter a new key to save.")
            return
        try:
            save(provider, value)
        except (CredentialStoreError, ValueError) as error:
            QMessageBox.warning(self, "Save failed", str(error))
            return
        field.clear()
        self._invalidate_test(provider)
        self._refresh(provider)
        if source.text().endswith("Environment"):
            QMessageBox.information(self, "Saved", "Saved to Windows Credential Manager. The environment variable still takes priority.")
        else:
            QMessageBox.information(self, "Saved", "Credential saved to Windows Credential Manager.")

    def _remove(self, provider):
        try:
            before = resolve(provider)
        except CredentialStoreError:
            QMessageBox.warning(self, "Store unavailable", "Cannot verify Windows Credential Manager.")
            return
        message = "Remove the saved Windows Credential Manager credential?"
        if before.source == "Windows Credential Manager":
            # A fallback may become active; warn explicitly before removal.
            message += "\n\nWarning: an existing legacy JSON credential may become active after removal. JSON files will not be changed."
        else:
            message += "\n\nEnvironment variables and legacy JSON files will not be changed."
        if QMessageBox.question(self, "Confirm removal", message, QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        try:
            removed = delete(provider)
        except CredentialStoreError as error:
            QMessageBox.warning(self, "Removal failed", str(error))
            return
        self._controls[provider][1].clear()
        self._invalidate_test(provider)
        self._refresh(provider)
        QMessageBox.information(self, "Removal", "Credential removed." if removed else "No stored credential was found.")

    def _test(self, provider):
        source, field, test, *_rest = self._controls[provider]
        status = self._controls[provider][5]
        if provider in self._workers:
            return
        key = field.text().strip()
        if not key:
            try:
                key = resolve(provider).value
            except CredentialStoreError:
                status.setText("Cannot access secure credential store")
                return
        if not key:
            status.setText("No credential available")
            return
        revision = self._test_revisions.get(provider, 0)
        worker = ConnectionWorker(provider, key)
        self._workers[provider] = worker
        test.setEnabled(False)
        status.setText("Testing connection...")
        worker.finished_test.connect(
            lambda p, result, r=revision: self._test_done(p, result, r)
        )
        worker.finished.connect(
            lambda p=provider, w=worker: self._worker_finished(p, w)
        )
        worker.start()

    def _test_done(self, provider, result, revision):
        if revision != self._test_revisions.get(provider, 0):
            return
        self._controls[provider][5].setText(result)

    def _worker_finished(self, provider, worker):
        if self._workers.get(provider) is worker:
            del self._workers[provider]
            self._controls[provider][2].setEnabled(True)
        worker.deleteLater()

    def closeEvent(self, event):
        if self._workers:
            QMessageBox.information(self, "Connection test running", "Wait for the connection test to finish before closing Settings.")
            event.ignore()
            return
        super().closeEvent(event)
