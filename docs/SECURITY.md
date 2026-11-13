# Security notes

CTI Workbench queries third-party intelligence services. Indicators entered into the application may therefore be transmitted to the configured services as part of enrichment. Review your organization's handling requirements before analyzing sensitive indicators.

## Data sent to providers

- Google Public DNS receives domain names and URL hostnames via DNS over HTTPS.
- RDAP.org receives domain names, URL hostnames, or IP addresses and can redirect requests to the responsible registry.
- IPinfo receives IP addresses for hostname and organization information.
- VirusTotal receives normalized indicators in read-only lookups when configured. URL lookups encode the normalized URL, including any retained query string and fragment.
- ThreatFox receives the hostname for URLs, or the domain, IP address or supported file hash for other lookups.
- URLhaus receives the normalized URL, including any retained query string and fragment, or the domain, IP address or supported file hash. Query strings may contain tokens or other sensitive data.

## Secrets

Real API credentials may be stored in Windows Credential Manager (preferred),
existing local configuration, or environment variables:

- Windows Credential Manager via Settings
- `config/virustotal.json`
- `config/abusech.json`
- `VT_API_KEY` / `ABUSECH_AUTH_KEY` environment variables

These paths are ignored by Git. Do not paste credentials into issues, commits, screenshots, documentation, or source files.

## Evidence model

CTI Workbench is evidence-first. It presents source-native findings from services such as VirusTotal, ThreatFox, and URLhaus. A relationship or lack of detections should not by itself be interpreted as proof that an indicator is malicious or benign.


## Local diagnostics

CTI Workbench writes rotating diagnostic logs to `logs/cti-workbench.log`. The directory is excluded from Git. Logs may contain indicators analyzed by the user, so treat them as operational CTI data and apply the same handling requirements as other investigation artifacts. API credentials are not intentionally logged.

## Credential handling

New credentials entered through Settings are saved with `keyring` in Windows
Credential Manager. Existing JSON files remain supported and are never migrated,
overwritten, or deleted automatically. Resolution order: environment variable,
Windows Credential Manager, legacy JSON. If the secure store is unavailable,
resolution fails closed rather than silently using legacy credentials.

Settings never displays existing secrets. Removing a Credential Manager entry
can reactivate an existing JSON credential. Connection tests are explicitly
initiated and send a fixed benign sample indicator to the relevant service;
no user IOC is submitted by the Settings test.
