# CTI Workbench v0.5.8

**Evidence-first IOC enrichment for Windows.**

CTI Workbench is a Windows desktop application for enriching indicators of compromise (IOCs) and presenting source-specific evidence in an analyst-oriented interface. Version 0.5.8 introduces a consolidated investigation overview and improves Intelligence Graph readability while retaining the existing evidence-first workflow.

## Current capabilities

- IOC analysis: IPv4, IPv6, IP:port, domain, URL, MD5, SHA-1 and SHA-256
- DNS / WHOIS enrichment through `iocinfo`
- VirusTotal API v3 existing-report enrichment and source-native vendor detection statistics
- ThreatFox and URLhaus API enrichment
- Automatic Related Indicators discovery when VirusTotal exposes relationship data
- Static, icon-based Intelligence Graph with relationship context and double-click pivoting
- Evidence-first global analysis state; no locally invented malware score
- Real pipeline checkpoints rather than simulated progress percentages
- Dark-only Windows analyst interface

## What's new in v0.5.8

- Consolidated, scrollable investigation overview with quick navigation and session-only recent searches
- Clearer presentation of the analyzed IOC, global assessment, individual intelligence sources and supporting context
- VirusTotal detection gauge and vendor statistics, explicitly separate from the global assessment
- Improved graph layout: compact radial arrangement for smaller indicator sets and two-column indicator lanes for dense graphs
- Unique graph nodes per indicator and type, with labels separated from nodes and relationship summaries outside the visualization
- Improved gauge-caption spacing and corrected the runtime issue identified during preview testing

The v0.5.8 interface and live API behavior were visually exercised on Windows before publication. The nine core normalization regression tests passed. These checks do not guarantee that every external API response or environment is covered.

## Quick start

**Requirements:** Windows 10/11 and Python 3.11+ recommended.

From PowerShell in the repository directory:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\setup.ps1
```

Add your own API credentials to the local configuration files created under `config`, then launch:

```powershell
.\run.ps1
```

See [`docs/SETUP.md`](docs/SETUP.md) for full setup instructions.

## API credentials and security

The repository includes configuration templates only:

- `config/virustotal.json.example`
- `config/abusech.json.example`

`setup.ps1` creates local working copies. Real credential files are excluded by `.gitignore` and **must never be committed**. VirusTotal integration looks up existing reports; CTI Workbench does not automatically upload files for scanning. TLS certificate verification remains enabled.

See [`docs/SECURITY.md`](docs/SECURITY.md) for additional security guidance.

## Analysis workflow

The application reports real pipeline checkpoints:

1. Validate and normalize the IOC
2. DNS / WHOIS enrichment
3. VirusTotal enrichment
4. ThreatFox enrichment
5. URLhaus enrichment
6. Related Indicators discovery
7. Intelligence Graph preparation

Related Indicators and the Intelligence Graph are populated automatically when relationship data is available.

### Interpreting results

**Zero detections does not mean safe.** VirusTotal vendor detections are displayed as VirusTotal-specific evidence, not as an overall safety score. A VirusTotal result with no detections does not override relevant evidence from ThreatFox or URLhaus. Related indicators show relationships, not automatic malicious verdicts.

## Analyst workflow

- Investigation overview with source evidence and supporting context
- Session-only recent searches and quick navigation
- Static Intelligence Graph with double-click pivoting
- Keyboard shortcuts: `Ctrl+L` focuses IOC input; `Ctrl+C` copies the current IOC; `Ctrl+E` exports related indicators
- Source response timing and relationship/graph timing
- Real checkpoints without fabricated progress percentages or decorative analysis animation

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
│   └── main.py
├── tests/
│   └── test_core.py
├── .gitignore
├── README.md
├── requirements.txt
├── run.ps1
└── setup.ps1
```

## Version history

- **v0.5.8:** Consolidated investigation overview; VirusTotal gauge and vendor statistics; refined Intelligence Graph layouts and labeling; runtime correction identified during preview testing.
- **v0.5.7:** Analyst UX refinements, Windows maximized startup, improved graph glyph sizing and relationship presentation.
- **v0.5.6:** Strict IP/IP:port validation, separation of core IOC/TLS/logging helpers from the UI, defensive VirusTotal relationship handling, rotating diagnostics, `iocinfo` timeout reporting and normalization regression tests.
- **v0.5.5:** Initial private GitHub release.

## Repository status

Current release: **v0.5.8**. This repository is intended to remain private unless its owner explicitly decides otherwise. No open-source license is granted by this repository.

## v0.6.1 development — Settings

The Settings gear allows storing VirusTotal and abuse.ch credentials in Windows
Credential Manager using `keyring`. Existing JSON configuration remains
compatible and unchanged. See `docs/SETUP.md` and `docs/SECURITY.md`.
