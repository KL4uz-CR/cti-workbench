# CTI Workbench v0.5.8 Preview 4 (test build)

Dense graphs now use two-column indicator lanes, retaining a compact radial layout for small sets. Labels are separated from nodes; graph relationship summaries remain outside the visualization. The gauge caption has additional clearance. This package includes the Preview 3 runtime NameError correction. Live API/UI regression testing is required on Windows before release. Do not commit API credentials.

# CTI Workbench v0.5.8 Preview 3 (reconstruida)

Cambios: versión visible corregida; grafo con nodos únicos por tipo e indicador, incluso cuando VirusTotal devuelve varias relaciones; distribución radial alternada; resumen de relaciones fuera del grafo. El odómetro continúa mostrando exclusivamente detecciones de VirusTotal, no una puntuación global de riesgo.

La validación visual y de las API debe realizarse en Windows antes de integrar en Git.

---

# CTI Workbench v0.5.8 — Visual preview 3

This is an early visual prototype based on the stable v0.5.7 rev 2 code. It preserves the existing source integrations, evidence logic, relationship table and static interactive graph. The interface now uses a continuous scrollable investigation view, quick navigation, recent searches (session-only), VirusTotal detection circle and vendor statistics.

This is a test build, not a validated release. The 9 core tests pass; live API/UI regression testing must be done on the user’s Windows machine. Do not commit local config JSON files or API keys.

Recent searches exist only during the running session. The circle reports VirusTotal vendor detections, **not** an overall safety score. No matches do not imply safety.

# CTI Workbench v0.5.7 rev 2

**Evidence-first IOC enrichment for Windows.**

CTI Workbench is a Windows desktop tool for quickly enriching indicators and presenting source evidence in a compact analyst-oriented interface. v0.5.7 refines the analyst UX while preserving the evidence-first, dark-only workflow.

## Current capabilities

- IOC analysis: IP, IP:port, domain, URL, MD5, SHA-1 and SHA-256
- DNS / WHOIS enrichment through `iocinfo`
- VirusTotal API v3 existing-report enrichment
- ThreatFox direct API enrichment
- URLhaus direct API enrichment
- Automatic Related Indicators discovery where the VirusTotal API exposes relationships
- Static icon-based Intelligence Graph with relationship labels and double-click pivoting
- Evidence-first global analysis state; no locally invented malware score
- Real pipeline progress checkpoints rather than time-based fake progress
- Dark-only analyst UI

## Quick start

Requirements: Windows 10/11 and Python 3.11+ recommended.

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\setup.ps1
```

Then add your own API credentials to the local files created under `config` and run:

```powershell
.\run.ps1
```

Full instructions: [`docs/SETUP.md`](docs/SETUP.md)

## API credentials

The repository contains **examples only**:

- `config/virustotal.json.example`
- `config/abusech.json.example`

`setup.ps1` copies these to local working files. Real credential files are excluded by `.gitignore` and must never be committed.

VirusTotal integration performs lookups of existing reports; CTI Workbench does not automatically upload files for scanning.

## Analysis workflow

The progress dialog reflects actual pipeline checkpoints:

1. Validate and normalize IOC
2. DNS / WHOIS enrichment
3. VirusTotal
4. ThreatFox
5. URLhaus
6. Related Indicators
7. Intelligence Graph

The indicator graph and Related Indicators are populated automatically when relationship data is available.

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



## v0.5.7 analyst UX

- Overview hierarchy: analyzed IOC → global finding → intelligence sources → context.
- Real checkpoint list during analysis; no fabricated time-based percentage.
- Per-source response timing plus relationship/graph timing.
- Keyboard shortcuts: Ctrl+L focus IOC, Ctrl+C copy current IOC, Ctrl+E export related indicators.
- Existing static Intelligence Graph and Related Indicators workflow retained.
- No proprietary malware score and no decorative analysis animation.

## v0.5.6 hardening

- Strict IPv4/IPv6 and IP:port validation using Python `ipaddress`
- Core IOC/TLS/logging helpers separated from the Qt UI
- Defensive validation of VirusTotal relationship payloads
- Rotating local diagnostics in `logs/cti-workbench.log` (excluded from Git)
- Explicit `iocinfo` executable and timeout diagnostics
- TLS verification remains enabled; certifi fallback is logged
- Regression tests for IOC normalization

## Important interpretation note

`0 detections` is not equivalent to `safe`. CTI Workbench keeps intelligence sources separate so that, for example, a VirusTotal result with no vendor detections does not suppress evidence returned by ThreatFox or URLhaus. Related indicators are relationships, not automatic malicious verdicts.

## Version

Current test baseline: **v0.5.7 rev 2**.

This repository is intended to remain private unless its owner explicitly decides otherwise. No open-source license is granted by this repository.


### v0.5.7 rev 2 visual refinement

- Starts maximized using the normal Windows maximized state (not exclusive fullscreen).
- Reduces peripheral Intelligence Graph glyphs to roughly half their previous footprint.
- Keeps the central analyzed IOC visually dominant at roughly 75% of its previous glyph size.
- Moves graph labels closer to the smaller glyphs while preserving the existing relationships and evidence model.


Preview 3: compact relationship graph for small IOC sets; relationship summary appears as a label below the graph, outside the visualization.
