# Changelog

## 0.7

- Embed iocinfo enrichment and distribute one self-contained Windows executable.
- Add English, Spanish and Brazilian Portuguese to the interface and Settings.
- Add the CTI Workbench icon to the interface and Windows executable.
- Report threat-intelligence coverage and distinguish partial results from insufficient data.
- Ignore documented legacy credential placeholders and skip unsupported SHA-1 lookups in ThreatFox and URLhaus.
- Remove the unencrypted IP geolocation lookup. Show ASN and organization when available from the remaining HTTPS sources.
- Apply the application's TLS context to VirusTotal report lookups and skip relationship queries when no report exists.
- Add Settings dialog and Windows Credential Manager integration.
- Preserve environment and legacy JSON credential compatibility.
- Add asynchronous, user-initiated connection tests.
- Centralize Python application version and synchronize setup banner.
- Add credential resolution and error-handling tests.
- Avoid including raw network exceptions in IOC lookup diagnostics.

## 0.5.8

- Previous stable release; unchanged in Git history.
