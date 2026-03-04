# DNS Enumeration Tool

> **Legal Disclaimer**
>
> This tool is intended for **authorized security testing and educational purposes only**.
> Only use it against domains and systems you own or have explicit written permission to test.
> Unauthorized use against systems you do not own may violate the Computer Fraud and Abuse Act (CFAA),
> the Computer Misuse Act, or equivalent laws in your jurisdiction.
>
> **The author assumes no liability for any misuse or damage caused by this tool.
> You are solely responsible for ensuring your use is legal and ethical.**

---

## Overview

A DNS enumeration tool for reconnaissance and security auditing. It queries DNS records,
brute-forces subdomains, tests for zone transfer vulnerabilities, and validates DNSSEC
configuration. Available as both an interactive CLI and a browser-based web UI.

**Built with:** Python 3, Flask, dnspython, requests

---

## Project Structure

```
domain-name-system-enumeration-tool/
├── dns_enum.py          # CLI entry point
├── start.sh             # macOS / Linux launcher (web UI)
├── start.bat            # Windows launcher (web UI)
├── requirements.txt
├── wordlists/
│   └── subdomain.txt    # Default wordlist (114,442 entries)
└── frontend/
    ├── app.py           # Flask web server entry point
    ├── index.html
    ├── style.css
    └── app.js
```

---

## Requirements

- Python 3.8+
- pip

Install dependencies manually if needed:

```bash
pip install -r requirements.txt
```

---

## Running the Web UI

The web UI exposes all features in a browser with a dark-themed interface.

**macOS / Linux:**
```bash
./start.sh
```

**Windows:**
```bat
start.bat
```

**Or manually:**
```bash
python frontend/app.py
```

Then open **http://127.0.0.1:5000** in your browser. The launcher will open it automatically.

---

## Running the CLI

**Interactive mode** (menu-driven):
```bash
python dns_enum.py
```

**CLI mode** (flags, scriptable):
```bash
python dns_enum.py -d example.com --dns-records
python dns_enum.py -d example.com --subdomains -w subdomain.txt
python dns_enum.py -d example.com --full-enum
python dns_enum.py -d example.com --zone-transfer
python dns_enum.py -d example.com --dnssec
python dns_enum.py -d example.com --full-enum --zone-transfer --dnssec
```

**All CLI flags:**

| Flag | Description |
|---|---|
| `-d`, `--domain` | Target domain |
| `--dns-records` | Enumerate DNS records |
| `--subdomains` | Enumerate subdomains |
| `--full-enum` | DNS records + subdomain enumeration combined |
| `--zone-transfer` | Test for zone transfer vulnerability |
| `--dnssec` | Check DNSSEC configuration |
| `-w`, `--wordlist` | Wordlist filename (from `wordlists/`) or absolute path |
| `--threads` | Number of concurrent threads (default: 50) |
| `--timeout` | Request timeout in seconds (default: 5) |
| `--list-wordlists` | List available wordlist files |
| `--quiet` | Suppress banner and status output |
| `--no-color` | Disable colored terminal output |
| `--help` | Show usage summary |
| `--help-detailed` | Show full help with examples |

CLI results are automatically saved to `.txt` files in the working directory.

---

## Modes

### DNS Records Enumeration
Queries all common DNS record types for a domain: `A`, `AAAA`, `CNAME`, `MX`, `NS`,
`TXT`, `SOA`, `SRV`, `PTR`, `NAPTR`, `CAA`, `DNSKEY`, `DS`, `TLSA`, `SSHFP`, `CERT`.
Also performs reverse DNS (PTR) lookups on any discovered IP addresses.

### Subdomain Enumeration
Brute-forces subdomains by iterating through a wordlist and probing each candidate over
HTTPS then HTTP. Reports status codes (200, 301/302, 401/403) and optionally includes
DNS-only results for hosts that resolve but don't respond to HTTP.
Runs with configurable concurrency (default 50 threads).

### Zone Transfer Check
Queries the domain's authoritative name servers and attempts an AXFR zone transfer
against each one. A successful transfer is a critical misconfiguration — it exposes the
entire DNS zone. Reports each server as vulnerable, refused (secure), or errored.

### DNSSEC Validation Check
Checks whether DNSSEC is configured by querying `DNSKEY`, `DS`, and `RRSIG` records.
Validates the chain of trust from the parent zone and runs an EDNS validation test.
Reports key types (KSK / ZSK), delegation status, and any configuration issues.

### Full Enumeration
Runs DNS Records, Subdomain Enumeration, Zone Transfer, and DNSSEC checks in sequence
for a single target. In the web UI this is displayed as a step-by-step progress report
with a combined summary at the end.

### Wordlists
Lists all `.txt` wordlist files in the `wordlists/` folder along with their line counts.
Additional wordlists (e.g. from [SecLists](https://github.com/danielmiessler/SecLists))
can be dropped into the `wordlists/` folder and will be picked up automatically.

---

## Adding Wordlists

Place any `.txt` file in the `wordlists/` folder. Each line should be a subdomain prefix
(e.g. `api`, `mail`, `dev`). The web UI and CLI will detect it automatically.

Recommended source: [SecLists DNS wordlists](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

---

## License

See [LICENSE](LICENSE).
