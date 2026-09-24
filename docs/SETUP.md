# Installation and configuration

## Requirements

- Windows 10/11 (64-bit recommended)
- Python 3.11+ recommended
- Internet access for IOC enrichment APIs and initial dependency installation
- VirusTotal API key
- abuse.ch Auth-Key for ThreatFox / URLhaus

## First-time setup

Open PowerShell in the repository directory:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\setup.ps1
```

The script creates `.venv`, installs `requirements.txt`, and creates local configuration files from the examples.

## API configuration

Edit `config\virustotal.json`:

```json
{
  "api_key": "YOUR_VIRUSTOTAL_API_KEY"
}
```

Edit `config\abusech.json`:

```json
{
  "auth_key": "YOUR_ABUSECH_AUTH_KEY"
}
```

Never commit either real file. They are explicitly excluded by `.gitignore`.

## Start

```powershell
.\run.ps1
```

## Supported input

- IPv4 / IPv6 where supported by the enrichment sources
- IP:port
- Domain
- URL
- MD5
- SHA-1
- SHA-256

## Troubleshooting

If `iocinfo` is not found or the environment becomes damaged, delete `.venv` and run `setup.ps1` again.

If API cards show `Not configured`, verify the corresponding JSON file and key.

Do not disable TLS certificate validation. The project uses `certifi` to maintain certificate verification.


## Self-test

After setup, core IOC normalization tests can be run with:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Runtime diagnostics are written to `logs\cti-workbench.log`.
