# ReconMap

ReconMap is a Zenmap-style desktop GUI for Kali/Linux that runs Nmap, captures raw output, parses XML results automatically, and highlights interesting services with suggested next steps.

## Features

- Run Nmap from a GUI
- Live raw output while the scan runs
- Automatic XML parsing when the scan finishes
- Hosts and services tables
- Interesting findings and recommended next steps
- Open existing XML files
- Save raw output and scan artifacts
- Packaged for `pipx`

## Requirements

- Linux/Kali
- `nmap` installed and available in `PATH`
- Python 3.10+

## Install for development

```bash
cd reconmap_project
pipx install .
reconmap
```

## Or run directly in a venv

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
reconmap
```

## Notes

- Some Nmap scan profiles require elevated privileges depending on your flags.
- The GUI does not itself escalate privileges.
