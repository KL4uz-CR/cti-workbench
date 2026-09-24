# Security notes

CTI Workbench queries third-party intelligence services. Indicators entered into the application may therefore be transmitted to the configured services as part of enrichment. Review your organization's handling requirements before analyzing sensitive indicators.

## Secrets

Real API credentials must remain only in:

- `config/virustotal.json`
- `config/abusech.json`

These paths are ignored by Git. Do not paste credentials into issues, commits, screenshots, documentation, or source files.

## Evidence model

CTI Workbench is evidence-first. It presents source-native findings from services such as VirusTotal, ThreatFox, and URLhaus. A relationship or lack of detections should not by itself be interpreted as proof that an indicator is malicious or benign.


## Local diagnostics

v0.5.6 writes rotating diagnostic logs to `logs/cti-workbench.log`. The directory is excluded from Git. Logs may contain indicators analyzed by the user, so treat them as operational CTI data and apply the same handling requirements as other investigation artifacts. API credentials are not intentionally logged.
