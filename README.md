# CTI Workbench

**Evidence-first IOC enrichment for Windows.**

CTI Workbench is a Windows desktop application for enriching indicators of compromise (IOCs) and presenting source-specific evidence in an analyst-oriented interface. The stable `v0.5.8` release introduced a consolidated investigation overview and improved Intelligence Graph readability while retaining the existing evidence-first workflow.

Version `0.7` packages CTI Workbench as a single portable Windows executable with embedded iocinfo, three interface languages, and evidence coverage in the assessment.

## Portable Windows build

Download the **CTI-Workbench-dev-win-x64** artifact from GitHub Actions and extract **CTI-Workbench.exe**. The executable includes Python, Qt and [iocinfo](https://github.com/homestarfuzzer/iocinfo) (MIT). It runs without an installer, an installed Python environment or a helper executable.

Online enrichment requires internet access. API keys saved in Windows Credential Manager and the language preference are specific to the Windows user. Optional legacy JSON credentials are read from the config directory next to the executable.

## Current capabilities

- IOC analysis: IPv4, IPv6, IP:port, domain, URL, MD5, SHA-1 and SHA-256.
- Built-in DNS / WHOIS and IP enrichment through iocinfo.
- Interface in English, Spanish and Brazilian Portuguese. Choose a language in Settings and restart to apply it.
- VirusTotal API v3 existing-report enrichment and source-native vendor detection statistics.
- ThreatFox and URLhaus API enrichment.
- Automatic Related Indicators discovery when VirusTotal exposes relationship data.
- Static, icon-based Intelligence Graph with relationship context and double-click pivoting.
- Evidence-first global analysis state; no locally invented malware score.
- Real pipeline checkpoints rather than simulated progress percentages.
- Dark-only Windows analyst interface.
- Settings dialog for API credential management.

## What's new in v0.5.8

- Consolidated, scrollable investigation overview with quick navigation and session-only recent searches.
- Clearer presentation of the analyzed IOC, global assessment, individual intelligence sources and supporting context.
- VirusTotal detection gauge and vendor statistics, explicitly separate from the global assessment.
- Improved graph layout: compact radial arrangement for smaller indicator sets and two-column indicator lanes for dense graphs.
- Unique graph nodes per indicator and type, with labels separated from nodes and relationship summaries outside the visualization.
- Improved gauge-caption spacing and corrected the runtime issue identified during preview testing.

The v0.5.8 interface and live API behavior were visually exercised on Windows before publication. The nine core normalization regression tests passed. These checks do not guarantee that every external API response or environment is covered.

## Quick start

**Requirements:** Windows 10/11 and Python 3.11+ recommended.

From PowerShell in the repository directory:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\setup.ps1
```

The setup script prepares the local environment and configuration files.

Configure your API credentials using the Settings dialog or the supported credential configuration mechanisms described in `docs/SETUP.md`. Then launch the application:

```powershell
.\run.ps1
```

See [`docs/SETUP.md`](docs/SETUP.md) for full setup instructions.

## API credentials and security

The repository includes configuration templates only:

- `config/virustotal.json.example`
- `config/abusech.json.example`

`setup.ps1` creates local working copies. Real credential files are excluded by `.gitignore` and **must never be committed**.

### Credential management

The Settings dialog allows users to manage VirusTotal and abuse.ch credentials through Windows Credential Manager using `keyring`.

Credential resolution follows this order:

1. Environment variables.
2. Windows Credential Manager.
3. Legacy JSON configuration, when the secure store is available but no credential is stored.

Supported environment variables:

- `VT_API_KEY` — VirusTotal.
- `ABUSECH_AUTH_KEY` — abuse.ch, including ThreatFox and URLhaus.

Existing JSON configuration remains compatible and unchanged. Saving credentials does not rewrite legacy JSON files. Removing a stored credential does not automatically delete environment variables or legacy JSON files.

The Settings dialog supports entering and saving credentials, testing connections, and removing stored credentials. Existing credentials are not automatically displayed in plaintext.

VirusTotal integration looks up existing reports; CTI Workbench does not automatically upload files for scanning. TLS certificate verification remains enabled.

See [`docs/SECURITY.md`](docs/SECURITY.md) for additional security guidance.

## Analysis workflow

The application reports real pipeline checkpoints:

1. Validate and normalize the IOC.
2. DNS / WHOIS enrichment.
3. VirusTotal enrichment.
4. ThreatFox enrichment.
5. URLhaus enrichment.
6. Related Indicators discovery.
7. Intelligence Graph preparation.

Related Indicators and the Intelligence Graph are populated automatically when relationship data is available.

### Interpreting results

**Zero detections does not mean safe.**

VirusTotal vendor detections are displayed as VirusTotal-specific evidence, not as an overall safety score. A VirusTotal result with no detections does not override relevant evidence from ThreatFox or URLhaus.

Related indicators show relationships, not automatic malicious verdicts.

Unavailable data, authentication failures, rate limits, and malformed responses must not be interpreted as evidence that an indicator is safe.

## Analyst workflow

- Investigation overview with source evidence and supporting context.
- Session-only recent searches and quick navigation.
- Static Intelligence Graph with double-click pivoting.
- Keyboard shortcuts: `Ctrl+L` focuses IOC input; `Ctrl+C` copies the current IOC; `Ctrl+E` exports related indicators.
- Source response timing and relationship/graph timing.
- Real checkpoints without fabricated progress percentages or decorative analysis animation.

## Repository layout

```text
cti-workbench/
├── config/
│   ├── abusech.json.example
│   └── virustotal.json.example
├── docs/
│   ├── SECURITY.md
│   └── SETUP.md
├── src/
│   ├── core.py
│   ├── credentials.py
│   ├── main.py
│   └── settings_dialog.py
├── tests/
│   ├── test_core.py
│   ├── test_credentials.py
│   └── test_sources.py
├── .gitignore
├── CHANGELOG.md
├── README.md
├── requirements.txt
├── run.ps1
└── setup.ps1
```

## Version history

- **v0.7:** Portable Windows executable, embedded iocinfo, English, Spanish and Brazilian Portuguese, and source coverage in the assessment.
- **v0.6.1-dev (development):** Secure credential management through Windows Credential Manager; Settings dialog; defensive ThreatFox and URLhaus response validation; improved IOCinfo logging privacy; 38 automated tests passed.
- **v0.5.8:** Consolidated investigation overview; VirusTotal gauge and vendor statistics; refined Intelligence Graph layouts and labeling; runtime correction identified during preview testing.
- **v0.5.7:** Analyst UX refinements, Windows maximized startup, improved graph glyph sizing and relationship presentation.
- **v0.5.6:** Strict IP/IP:port validation, separation of core IOC/TLS/logging helpers from the UI, defensive VirusTotal relationship handling, rotating diagnostics, `iocinfo` timeout reporting and normalization regression tests.
- **v0.5.5:** Initial private GitHub release.

## Repository status

- **Version on `develop`:** `v0.7`.
- **Previous stable baseline:** `v0.5.8`.

This repository is intended to remain private unless its owner explicitly decides otherwise. No open-source license is granted by this repository.

## v0.6.1-dev — Secure credentials and CTI source validation

The Settings dialog allows users to manage VirusTotal and abuse.ch credentials through Windows Credential Manager.

ThreatFox response handling distinguishes explicit no-result responses from authentication errors and invalid response structures.

URLhaus response handling validates response status and data structures before reporting an indicator as found. Empty host results, invalid URL collections, and incomplete hash responses are handled defensively.

IOCinfo execution logging avoids recording the complete IOC in routine analysis logs. Execution errors no longer expose exception details directly to the user.

The Settings dialog also prevents stale connection-test results from overwriting newer status information after credential changes and includes QThread lifecycle management for connection tests.

**Automated validation:** 38 tests passed, covering IOC normalization, credential resolution and validation, and ThreatFox and URLhaus response handling. The tests do not constitute exhaustive validation of every UI workflow or external API response.

See [`docs/SETUP.md`](docs/SETUP.md) for setup instructions and [`docs/SECURITY.md`](docs/SECURITY.md) for security guidance.

## Development and testing

Development takes place on the `develop` branch. The `main` branch represents the stable release line.

Run the automated tests from PowerShell using the existing virtual environment:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Compile-check the principal application modules:

```powershell
.\.venv\Scripts\python.exe -m py_compile .\src\main.py .\src\core.py
```

Before committing changes:

1. Review the current branch and working-tree status.
2. Inspect changes and run `git diff --check`.
3. Review staged files and ensure that secrets are not included.
4. Run the relevant automated tests.
5. Commit on `develop` and publish only after the changes have been reviewed.

Do not modify historical release tags or rewrite published Git history.

## Security principles

- Keep TLS certificate verification enabled.
- Never commit API keys, tokens, or other secrets.
- Keep `.venv`, local credential files, and application logs excluded from Git.
- Respect API authentication requirements, timeouts, and rate limits.
- Validate external response structures before reporting positive findings.
- Do not interpret source errors or unavailable information as clean intelligence results.
- Do not upload files automatically to VirusTotal.
- Do not invent detection counts, malware classifications, relationships, or confidence values.

## Project status

CTI Workbench is a personal technical development project focused on evidence-based IOC enrichment and practical SOC/CTI investigation workflows.

Version 0.7 brings the changes developed during the 0.6 cycle together.

No claim is made that the application is signed, packaged as a production-ready executable, or deployed as a production service.

The repository remains private unless its owner explicitly authorizes a change in visibility or licensing.