"""Manual credential settings; no existing secrets are displayed in fields."""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QComboBox, QDialog, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel, QLineEdit,
    QPushButton, QMessageBox, QWidget,
)

from localization import LANGUAGES, save_language, selected_language, tr
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
        self.setWindowTitle(tr("Settings")+" — CTI Workbench")
        self.setMinimumWidth(510)
        self._workers = {}
        self._test_revisions = {}
        self._controls = {}
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(tr("API credentials are stored in Windows Credential Manager.")))
        layout.addWidget(QLabel(tr("Existing credentials are never shown or changed automatically.")))
        for provider, title in (("virustotal", "VirusTotal"), ("abusech", "abuse.ch (ThreatFox / URLhaus)")):
            group = QGroupBox(title)
            form = QVBoxLayout(group)
            source = QLabel(tr("Credential source: checking..."))
            form.addWidget(source)
            entry_row = QHBoxLayout()
            field = QLineEdit()
            field.setEchoMode(QLineEdit.Password)
            field.setPlaceholderText(tr("Enter a new key (leave blank to keep current)"))
            entry_row.addWidget(field)
            show = QPushButton(tr("Show"))
            show.setCheckable(True)
            show.toggled.connect(lambda checked, f=field, b=show: self._toggle(f, b, checked))
            entry_row.addWidget(show)
            form.addLayout(entry_row)
            buttons = QHBoxLayout()
            test = QPushButton(tr("Test Connection"))
            store = QPushButton(tr("Save"))
            remove = QPushButton(tr("Remove"))
            test.setObjectName("testButton")
            store.setObjectName("saveButton")
            remove.setObjectName("removeButton")
            store.setStyleSheet(
                "QPushButton#saveButton{background:#145C55;color:#FFFFFF;"
                "border:1px solid #1D8A7B;font-weight:750}"
                "QPushButton#saveButton:hover{background:#187468}"
            )
            remove.setToolTip(tr("Remove the stored credential"))
            remove.setStyleSheet(
                "QPushButton#removeButton{background:#3B2D20;color:#F6C98B;"
                "border:1px solid #80603A;font-weight:600}"
                "QPushButton#removeButton:hover{background:#513A25;"
                "border-color:#B78A50}"
            )
            for button in (test, store, remove):
                buttons.addWidget(button)
            form.addLayout(buttons)
            status = QLabel(tr("Not tested"))
            form.addWidget(status)
            self._controls[provider] = (source, field, test, store, remove, status)
            field.textChanged.connect(
                lambda _text, p=provider: self._invalidate_test(p)
            )
            test.clicked.connect(lambda checked=False, p=provider: self._test(p))
            store.clicked.connect(lambda checked=False, p=provider: self._save(p))
            remove.clicked.connect(lambda checked=False, p=provider: self._remove(p))
            layout.addWidget(group)
        language_row = QHBoxLayout()
        language_label = QLabel(tr("Language"))
        language = QComboBox()
        language_label.setBuddy(language)
        for code, name in LANGUAGES.items():
            language.addItem(name, code)
        language.setCurrentIndex(language.findData(selected_language()))
        language.activated.connect(lambda index: self._save_language(language.itemData(index)))
        language_row.addWidget(language_label)
        language_row.addWidget(language, 1)
        layout.addLayout(language_row)

        close = QPushButton(tr("Close"))
        close.clicked.connect(self.close)
        layout.addWidget(close)
        self._refresh_all()

    def _save_language(self, language):
        if language == selected_language():
            return
        if save_language(language):
            QMessageBox.information(self, tr("Language"), tr("Language saved. Restart CTI Workbench to apply the change."))
        else:
            QMessageBox.warning(self, tr("Language"), tr("Could not save the language preference."))

    @staticmethod
    def _toggle(field, button, checked):
        field.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)
        button.setText(tr("Hide") if checked else tr("Show"))

    def _invalidate_test(self, provider):
        self._test_revisions[provider] = self._test_revisions.get(provider, 0) + 1
        self._controls[provider][5].setText(tr("Not tested"))

    def _refresh_all(self):
        for provider in self._controls:
            self._refresh(provider)

    def _refresh(self, provider):
        label = self._controls[provider][0]
        try:
            credential = resolve(provider)
            label.setText(tr("Credential source: ") + tr(credential.source))
        except CredentialStoreError:
            label.setText(tr("Windows Credential Manager unavailable. Check its availability and try again."))

    def _save(self, provider):
        source, field, *_ = self._controls[provider]
        value = field.text().strip()
        if not value:
            QMessageBox.information(self, tr("No changes"), tr("Enter a new key to save."))
            return
        try:
            save(provider, value)
        except (CredentialStoreError, ValueError) as error:
            QMessageBox.warning(self, tr("Save failed"), tr(str(error)))
            return
        field.clear()
        self._invalidate_test(provider)
        self._refresh(provider)
        if source.text().endswith(tr("Environment")):
            QMessageBox.information(self, tr("Saved"), tr("Saved to Windows Credential Manager. The environment variable still takes priority."))
        else:
            QMessageBox.information(self, tr("Saved"), tr("Credential saved to Windows Credential Manager."))

    def _remove(self, provider):
        try:
            before = resolve(provider)
        except CredentialStoreError:
            QMessageBox.warning(self, tr("Store unavailable"), tr("Cannot verify Windows Credential Manager."))
            return
        message = "Remove the saved Windows Credential Manager credential?"
        if before.source == "Windows Credential Manager":
            # A fallback may become active; warn explicitly before removal.
            message += "\n\n" + tr("Warning: an existing legacy JSON credential may become active after removal. JSON files will not be changed.")
        else:
            message += "\n\n" + tr("Environment variables and legacy JSON files will not be changed.")
        if QMessageBox.question(self, tr("Confirm removal"), message, QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        try:
            removed = delete(provider)
        except CredentialStoreError as error:
            QMessageBox.warning(self, tr("Removal failed"), tr(str(error)))
            return
        self._controls[provider][1].clear()
        self._invalidate_test(provider)
        self._refresh(provider)
        QMessageBox.information(self, tr("Removal"), tr("Credential removed.") if removed else tr("No stored credential was found."))

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
                status.setText(tr("Cannot access secure credential store"))
                return
        if not key:
            status.setText(tr("No credential available"))
            return
        revision = self._test_revisions.get(provider, 0)
        worker = ConnectionWorker(provider, key)
        self._workers[provider] = worker
        test.setEnabled(False)
        status.setText(tr("Testing connection..."))
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
            QMessageBox.information(self, tr("Connection test running"), tr("Wait for the connection test to finish before closing Settings."))
            event.ignore()
            return
        super().closeEvent(event)
