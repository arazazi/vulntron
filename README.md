<div align="center">

# 🛡️ Vulntron

### Defensive Vulnerability Assessment and Reporting Tool

*Authorized network vulnerability scanning with evidence-based findings and professional reporting*

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)]()
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-4.0.0-success.svg)]()

</div>

---

**Vulntron** is a defensive vulnerability assessment and reporting tool designed for use in authorized environments. It performs TCP port discovery, service fingerprinting, targeted vulnerability checks with evidence, compliance assessment, CVE enrichment via the NVD API, and generates both HTML and JSON reports.

> **⚠️ Authorized use only.** Vulntron must only be run against systems you own or have explicit written permission to scan. See the [Safety, Ethics, and Authorization](#-safety-ethics-and-authorization) section.

---

## 📋 Table of Contents

1. [Features](#-features)
2. [Safety, Ethics, and Authorization](#-safety-ethics-and-authorization)
3. [Architecture Overview](#-architecture-overview)
4. [Credentialed Scanning](#-credentialed-scanning)
5. [Installation](#-installation)
6. [Quick Start](#-quick-start)
7. [CLI Reference](#-cli-reference)
8. [Understanding Results](#-understanding-results)
9. [Report Formats](#-report-formats)
10. [Examples](#-examples)
11. [Troubleshooting](#-troubleshooting)
12. [Development](#-development)
13. [Known Limitations](#-known-limitations)
14. [Roadmap](#-roadmap)
15. [License](#-license)

---

## ✨ Features

### 🔍 Port Discovery Modes

Vulntron supports four TCP port scan modes to match the scope of your assessment:

| Mode | Coverage | Typical Use |
|------|----------|-------------|
| `common` *(default)* | 22 well-known ports (FTP, SSH, SMTP, HTTP, HTTPS, SMB, RDP, MySQL, etc.) | Fast initial triage |
| `top1000` | ~1,000 most commonly open ports, including high-numbered RPC and SSDP ranges | General-purpose assessment |
| `full` | All 65,535 TCP ports | Thorough audit of legacy or misconfigured hosts |
| `custom` | User-defined list or ranges (e.g., `21,80,443,1025-1030`) | Targeted re-scan of specific services |

### 🖧 Service Fingerprinting

For each open port, Vulntron performs a banner-grab to identify the service and version string. Results are included in both reports.

### 🔎 Vulnerability Checks with Evidence

Vulntron runs active, evidence-based checks against detected services:

| Check | Target | CVE / ID | Default Severity |
|-------|--------|----------|-----------------|
| EternalBlue | SMB port 445 | CVE-2017-0144 (MS17-010) | CRITICAL |
| SMBGhost | SMB port 445 | CVE-2020-0796 | HIGH |
| BlueKeep | RDP port 3389 | CVE-2019-0708 | HIGH |
| Missing HTTP security headers | Ports 80, 443, 8080, 8443 | — | MEDIUM |
| Exposed database service | Ports 3306, 5432, 1433, 27017, 6379 | — | HIGH |
| **FTP anonymous login** | FTP port 21 | — | HIGH (if CONFIRMED) |
| **Telnet service exposure** | Telnet port 23 | — | HIGH (POTENTIAL) |
| **SNMP default community** | SNMP port 161 | — | HIGH (if CONFIRMED) |

Each finding is assigned a status of **CONFIRMED**, **POTENTIAL**, or **INCONCLUSIVE** based on the quality of evidence collected.

### 📋 Compliance Assessment

Vulntron optionally evaluates findings against **PCI DSS 3.2.1** requirements and produces a pass/fail score with a list of failing controls.

### 📄 HTML + JSON Reporting

- **HTML report**: A self-contained, color-coded dashboard with an executive summary, per-finding details, port table, and compliance results.
- **JSON report**: A machine-readable file covering all phases, suitable for ingestion by SIEMs, ticketing systems, or further automation.

Report filenames follow the pattern:
```
vultron_hybrid_<target>_<YYYYMMDD_HHMMSS>.html
vultron_hybrid_<target>_<YYYYMMDD_HHMMSS>.json
```

### 🌐 CVE Enrichment and Fallback Handling

Vulntron queries the **NVD API 2.0** for CVEs published in the last N days (configurable via `--cve-lookback-days`, default 120). If the API is unreachable, rate-limited, or returns an error:

- Retries are attempted (up to 3 times with exponential back-off).
- On final failure the enrichment phase is skipped gracefully; all other results are preserved.
- A warning is printed so operators are aware enrichment data may be incomplete.

---

## ⚠️ Safety, Ethics, and Authorization

Vulntron is a **defensive** tool built exclusively for:

- Assessing systems you own or administer.
- Authorized penetration tests with written consent from the asset owner.
- Lab and training environments under your direct control.

**Unauthorized scanning is illegal** in most jurisdictions (e.g., the Computer Fraud and Abuse Act in the United States, the Computer Misuse Act in the United Kingdom, and equivalent laws elsewhere). Running Vulntron against systems without explicit written authorization may result in criminal prosecution, civil liability, and permanent professional consequences.

By using Vulntron you agree that:

1. You have verified you are authorized to scan every target IP or hostname you supply.
2. You will not use scan results to exploit, damage, or disrupt any system.
3. You accept sole responsibility for lawful and ethical use.

If you are unsure whether you have authorization, **do not run the scan**.

---

## 🏗️ Architecture Overview

### High-level scan pipeline

```
User supplies target + options
        │
        ▼
┌───────────────────┐
│  PHASE 1          │  TCP connect scan (multi-threaded, configurable concurrency)
│  Port Discovery   │  → Banner grabbing per open port
└────────┬──────────┘
         │  open ports + banners
         ▼
┌───────────────────┐
│  PHASE 2          │  Protocol-specific probes (SMB, RDP, HTTP, DB)
│  Vuln Checks      │  → Evidence collected → CONFIRMED / POTENTIAL / INCONCLUSIVE
│  (Plugin checks)  │  → Legacy VulnerabilityChecker + adapter → unified Finding schema
└────────┬──────────┘
         │  unified Finding objects (serialised as dicts)
         ▼
┌───────────────────┐
│  PHASE 3          │  NVD API 2.0 query (configurable lookback, default 120 days)
│  CVE Enrichment   │  → Retry / graceful fallback on API errors
└────────┬──────────┘
         │  enriched findings
         ▼
┌───────────────────┐
│  PHASE 4          │  PCI DSS 3.2.1 evaluation (optional, --skip-compliance)
│  Compliance       │  → Pass / Fail score + issue list
└────────┬──────────┘
         │  all results + scan metadata
         ▼
┌───────────────────┐
│  PHASE 5          │  HTML dashboard + JSON data file
│  Report Gen       │  → Saved to working directory
└───────────────────┘
```

### Phase A — Plugin Framework (`plugins/`)

Phase A introduced a modular plugin system and a unified finding schema as the foundation for future phases.

#### Package layout

```
plugins/
├── __init__.py       # Public API: BaseCheck, CheckRegistry, Finding, ScanMetadata, Evidence
├── schema.py         # Finding, Evidence, ScanMetadata dataclasses (unified schema)
├── base.py           # BaseCheck abstract class (check contract)
├── registry.py       # CheckRegistry (registration and port/service dispatch)
└── checks/
    ├── __init__.py   # Auto-imports smb and network to register all built-in checks
    ├── smb.py        # EternalBlueCheck, SMBGhostCheck
    └── network.py    # BlueKeepCheck, FTPAnonCheck, TelnetBannerCheck,
                      # SNMPCommunityCheck, DatabaseExposureCheck, WebHeadersCheck
```

#### Unified Finding schema

Every check result is represented as a `Finding` object defined in `plugins/schema.py`.  Key fields:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `str` | Stable check/finding ID (e.g. `MS17-010`) |
| `title` | `str` | Short human-readable title |
| `description` | `str` | Full description |
| `status` | `str` | `CONFIRMED` / `POTENTIAL` / `INCONCLUSIVE` / `NOT_AFFECTED` |
| `severity` | `str` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO` |
| `confidence` | `float` | 0.0–1.0 (CONFIRMED=0.9, POTENTIAL=0.5, INCONCLUSIVE=0.2) |
| `target` | `str` | Host/IP scanned |
| `port` | `int?` | Port number, or `None` |
| `service` | `str?` | Service name, or `None` |
| `evidence` | `Evidence` | `items: List[str]` + optional `raw: str` |
| `cve_refs` | `List[str]` | CVE identifiers (e.g. `["CVE-2017-0144"]`) |
| `cvss` | `float?` | CVSS base score, or `None` |
| `remediation` | `str?` | Recommended remediation |
| `cisa_kev` | `bool` | Whether listed in CISA KEV catalogue |
| `exploit_available` | `bool` | Public exploit known |

`ScanMetadata` captures scan-level context: `scan_id` (UUID4), `target`, `started`/`ended` (ISO-8601), and `config` (timeout, retries, concurrency, mode).

#### Backward compatibility

`Finding.from_legacy_dict()` adapts any dict produced by the existing `VulnerabilityChecker` methods into a `Finding` object.  `Finding.to_dict()` serialises it back to a dict that contains **all original keys** plus the new unified fields.  This means no existing code or tests need to change.

The pipeline applies this adapter automatically: `VulnerabilityChecker` still runs all checks unchanged; its output dicts are promoted to `Finding` objects and then serialised with the enriched keys before being stored in `results['vulnerabilities']`.

#### Adding a new plugin check

1. Create or add to a file in `plugins/checks/` (or anywhere on the Python path).
2. Subclass `BaseCheck` and decorate with `@CheckRegistry.register`:

```python
from plugins import BaseCheck, CheckRegistry, Evidence, Finding

@CheckRegistry.register
class MyServiceCheck(BaseCheck):
    check_id         = 'MY-SERVICE-001'   # stable, unique ID
    title            = 'My Service Exposure'
    description      = 'Detects insecure exposure of My Service on port 9999.'
    category         = 'network'          # 'network' | 'service' | 'config'
    default_severity = 'HIGH'
    required_ports   = [9999]             # used by CheckRegistry.checks_for_port()
    service_matchers = ['MyService']      # matched case-insensitively

    def run(self, target: str, port: int = 9999, **kwargs):
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            sock.close()
            return [Finding(
                id=self.check_id, title=self.title,
                description='My Service is reachable from an external host.',
                status='CONFIRMED', severity=self.default_severity,
                confidence=0.9, target=target, port=port, service='MyService',
                evidence=Evidence(items=[f'Port {port}/tcp accepted connection']),
                remediation='Restrict access via firewall.',
            )]
        except socket.timeout:
            return [Finding(
                id=self.check_id, title=self.title + ' — inconclusive (timeout)',
                description='Probe timed out.',
                status='INCONCLUSIVE', severity=self.default_severity,
                confidence=0.2, target=target, port=port,
            )]
        except Exception:
            return []
```

3. Import the module in `plugins/checks/__init__.py` to auto-register it:

```python
from . import my_module  # noqa: F401
```

4. Discover it via the registry:

```python
from plugins import CheckRegistry
checks = CheckRegistry.checks_for_port(9999)
findings = [f for check_cls in checks for f in check_cls().run(target, 9999)]
```

---

## 🔑 Credentialed Scanning

> **⚠️ Authorized use only.** Credentialed scanning connects to targets using authentication credentials. Only use this feature on systems you own or have explicit written permission to assess. Never share or commit real credentials to version control.

Vultron supports **authenticated scanning** (PR1) for Linux/Unix and Windows targets via SSH, WinRM, and WMI. Credentialed scans can verify patch status, configuration, and service health in ways that unauthenticated probes cannot.

### Supported Authentication Methods

| Protocol | Auth Methods | Default Port | OS Targets |
|----------|-------------|-------------|------------|
| SSH | Password, private key (RSA/ECDSA/Ed25519) | 22 | Linux, macOS, Unix-like |
| WinRM | Username + password (NTLM/Kerberos) | 5985 (HTTP) / 5986 (HTTPS) | Windows |
| WMI | Username + password | 135 (DCOM) | Windows |

### Quick Start — Credentialed Scanning

**SSH with password:**

```bash
python3 vultron.py -t 192.168.1.100 --ssh-user scanuser --ssh-password '<your-password>'
```

**SSH with private key:**

```bash
python3 vultron.py -t 192.168.1.100 --ssh-user scanuser --ssh-key /path/to/id_rsa
```

**WinRM (Windows Remote Management):**

```bash
python3 vultron.py -t 192.168.1.100 --winrm-user Administrator --winrm-password '<your-password>'
```

**WinRM with domain:**

```bash
python3 vultron.py -t 192.168.1.100 --winrm-user Administrator --winrm-domain CORP --winrm-password '<your-password>'
```

**WMI (Windows Management Instrumentation):**

```bash
python3 vultron.py -t 192.168.1.100 --wmi-user Administrator --wmi-password '<your-password>'
```

**Credentials from a file (recommended over CLI flags for automation):**

```bash
python3 vultron.py -t 192.168.1.100 --cred-file /secure/path/credentials.json
```

**Credentials from environment variables (CI / automation):**

```bash
export VULTRON_SSH_USER=scanuser
export VULTRON_SSH_PASSWORD=<your-password>
python3 vultron.py -t 192.168.1.100
```

### Credential File Format

Create a JSON file at a secure location (not inside the repository). Example structure with **placeholder values only**:

```json
{
    "ssh": {
        "username": "<your-ssh-username>",
        "password": "<your-ssh-password-or-omit-for-key-auth>",
        "key_path": "/path/to/private/key",
        "port": 22
    },
    "winrm": {
        "username": "<your-winrm-username>",
        "password": "<your-winrm-password>",
        "domain": "<optional-ad-domain>",
        "transport": "http"
    },
    "wmi": {
        "username": "<your-wmi-username>",
        "password": "<your-wmi-password>",
        "domain": "<optional-ad-domain>"
    }
}
```

> All top-level keys (`ssh`, `winrm`, `wmi`) are optional. Include only the protocols you need.
> **Never commit a credentials file to version control.** Add it to `.gitignore`.

### Environment Variable Reference

| Variable | Description |
|----------|-------------|
| `VULTRON_SSH_USER` | SSH username |
| `VULTRON_SSH_PASSWORD` | SSH password (omit when using a key) |
| `VULTRON_SSH_KEY_PATH` | Path to SSH private key file |
| `VULTRON_SSH_PASSPHRASE` | Passphrase for a protected private key |
| `VULTRON_SSH_PORT` | SSH port (default `22`) |
| `VULTRON_WINRM_USER` | WinRM username |
| `VULTRON_WINRM_PASSWORD` | WinRM password |
| `VULTRON_WINRM_DOMAIN` | Active Directory domain (optional) |
| `VULTRON_WINRM_TRANSPORT` | WinRM transport: `http` or `https` (default `http`) |
| `VULTRON_WINRM_PORT` | WinRM port override (optional) |
| `VULTRON_WMI_USER` | WMI username |
| `VULTRON_WMI_PASSWORD` | WMI password |
| `VULTRON_WMI_DOMAIN` | Active Directory domain (optional) |
| `VULTRON_WMI_NAMESPACE` | WMI namespace (default `root/cimv2`) |

### Credential Provider Precedence

Credentials are resolved in the following order:

1. **Inline CLI flags** (`--ssh-user`, `--ssh-password`, etc.)
2. **Environment variables** (`VULTRON_SSH_USER`, etc.)
3. **Credential file** (`--cred-file`)

The first non-empty source wins for each protocol independently.

### Optional Dependencies for Full Authentication

PR1 includes full TCP-layer reachability checks without additional dependencies. For full session authentication, install the relevant library:

| Protocol | Library | Install |
|----------|---------|---------|
| SSH (key/password auth) | `paramiko` | `pip install paramiko` |
| WinRM (session auth) | `pywinrm` | `pip install pywinrm` |
| WMI (namespace auth) | `impacket` | `pip install impacket` |

Without these libraries, Vultron falls back to **TCP connectivity verification** only and reports this clearly in the finding evidence.

### Security Design

- Credentials are **never** written to HTML/JSON reports, log files, or the console.
- Exception messages containing credential-like strings are sanitised before output.
- The `--ssh-password` and `--ssh-key` flags are **mutually exclusive**; providing both is an error.
- All probes are **non-invasive** — no write operations, no configuration changes.
- `INFO` severity findings are used for authenticated probe results to distinguish them from vulnerability findings.

### Credentialed Scan Output

The JSON report includes an `auth_scan` field with probe results (no secrets):

```json
{
  "auth_scan": {
    "authenticated_mode": true,
    "credentials_configured": {
      "ssh": "SSHCredential(user='scanuser', auth='key', port=22)",
      "winrm": null,
      "wmi": null
    },
    "probe_results": {
      "ssh": {
        "protocol": "ssh",
        "target": "192.168.1.100",
        "port": 22,
        "success": true,
        "message": "SSH connectivity and authentication confirmed on 192.168.1.100:22",
        "error": null,
        "latency_ms": null
      }
    }
  }
}
```

### Limitations and Next Steps

- **PR1 scope**: TCP connectivity and basic authentication probes only. Credentialed vulnerability checks (OS patch status, software inventory, configuration audits) are planned for subsequent PRs.
- WinRM and WMI authentication require `pywinrm` and `impacket` respectively. TCP-only verification is available without them.
- Windows Kerberos authentication is not yet supported (NTLM only via WinRM).
- Future PRs will extend credentialed checks to cover patching status, compliance baselines, and service configurations.

---

## 📥 Installation

### Prerequisites

| Requirement | Notes |
|-------------|-------|
| Python 3.8+ | Download from [python.org](https://www.python.org/downloads/) |
| pip | Included with Python 3.4+ |
| Network access to target | Required for scanning |
| Internet access (optional) | Required for NVD CVE enrichment |

No system-level tools (nmap, etc.) are required; Vulntron uses Python's `socket` library for port scanning.

### Clone and Install

```bash
git clone https://github.com/arazazi/vulntron.git
cd vulntron

pip install -r requirements.txt
```

### Verify Installation

```bash
python3 vultron.py --version
```

Expected output: `Vultron 4.0.0`

> **Note:** The tool's internal name is `Vultron`; the repository is hosted as `vulntron`. Both names refer to the same project.

### NVD API Key (Optional but Recommended)

Without an API key, the NVD API limits requests to 5 per 30 seconds. A free key increases this to 50 per 30 seconds and reduces the likelihood of rate-limit errors during enrichment.

1. Request a free key at: <https://nvd.nist.gov/developers/request-an-api-key>
2. Open `vultron.py` and replace the value of `NVD_API_KEY` near the top of the file with your key.

```python
NVD_API_KEY = "your-key-here"
```

> **Note:** The repository ships with a placeholder key. Rotate to your own key for production use.

---

## ⚡ Quick Start

### Default scan (22 common ports)

```bash
python3 vultron.py -t 192.168.1.10
```

### Full port scan (all 65,535 TCP ports)

```bash
python3 vultron.py -t 192.168.1.10 --scan-mode full
```

### Top-1000 port scan, skip compliance

```bash
python3 vultron.py -t 192.168.1.10 --scan-mode top1000 --skip-compliance
```

### Custom port list

```bash
python3 vultron.py -t 192.168.1.10 --scan-mode custom --ports 21,22,80,443,445,3389
```

### Tuning timeout, retries, and concurrency

```bash
python3 vultron.py -t 192.168.1.10 --timeout 2.0 --retries 2 --concurrency 100
```

### Skip NVD enrichment (offline / air-gapped environments)

```bash
python3 vultron.py -t 192.168.1.10 --skip-nvd
```

### Narrow CVE lookback window (last 30 days only)

```bash
python3 vultron.py -t 192.168.1.10 --cve-lookback-days 30
```

### Extend CVE lookback window (last year)

```bash
python3 vultron.py -t 192.168.1.10 --cve-lookback-days 365
```

### Scan for legacy protocols (FTP, Telnet, SNMP)

```bash
python3 vultron.py -t 192.168.1.10 --scan-mode custom --ports 21,23,161
```

### Save reports to a specific directory

Reports are written to the current working directory. Change directory before running to control output location:

```bash
mkdir -p /tmp/scan-results && cd /tmp/scan-results
python3 /path/to/vultron.py -t 192.168.1.10
```

---

## 📖 CLI Reference

```
python3 vultron.py -t <target> [options]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-t`, `--target` | string | *(required)* | Target IP address or hostname |
| `--scan-mode` | choice | `common` | Port scan coverage: `common`, `top1000`, `full`, `custom` |
| `--ports` | string | — | Custom port list/ranges. Required when `--scan-mode custom` (e.g. `21,80,443,1025-1030`) |
| `--timeout` | float | `1.0` | Per-port TCP connection timeout in seconds |
| `--retries` | int | `1` | Number of retry attempts per port on failure |
| `--concurrency` | int | `50` | Maximum number of concurrent port scan threads |
| `--skip-nvd` | flag | `False` | Skip NVD CVE enrichment (useful for air-gapped or offline use) |
| `--skip-compliance` | flag | `False` | Skip PCI DSS compliance assessment |
| `--cve-lookback-days` | int | `120` | Days to look back when querying NVD for recent CVEs (range: 1–3650) |
| `--version` | flag | — | Show version string and exit |

### Credentialed Scanning Options (authorized use only)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--cred-file` | path | — | Path to a JSON credential file |
| `--ssh-user` | string | — | SSH username |
| `--ssh-password` | string | — | SSH password (mutually exclusive with `--ssh-key`) |
| `--ssh-key` | path | — | Path to SSH private key file |
| `--ssh-port` | int | `22` | SSH port |
| `--winrm-user` | string | — | WinRM username |
| `--winrm-password` | string | — | WinRM password |
| `--winrm-domain` | string | — | Active Directory domain (optional) |
| `--winrm-transport` | choice | `http` | WinRM transport: `http` or `https` |
| `--wmi-user` | string | — | WMI username |
| `--wmi-password` | string | — | WMI password |
| `--wmi-domain` | string | — | Active Directory domain (optional) |

---

## 🔬 Understanding Results

### Finding Status

Every vulnerability finding is assigned one of three statuses:

| Status | Meaning |
|--------|---------|
| **CONFIRMED** | An active probe returned definitive evidence of the vulnerability or misconfiguration (e.g., SMBv1 negotiation succeeded, security headers are absent in an HTTP response). |
| **POTENTIAL** | The port/service combination is associated with a known vulnerability, but version information could not be verified. Treat as a lead requiring further manual validation. |
| **INCONCLUSIVE** | The check was attempted but could not be completed (e.g., the connection timed out, a network error interrupted the probe). **A timeout does not imply the system is vulnerable.** |

### Severity vs. Confidence

- **Severity** (CRITICAL / HIGH / MEDIUM / LOW) reflects the worst-case impact *if* the vulnerability is present and exploitable.
- **Status** reflects Vulntron's confidence in the finding.

Summary counters (e.g., "Critical: 1") count only **CONFIRMED** findings at that severity. POTENTIAL and INCONCLUSIVE findings are reported separately so operators can distinguish confirmed issues from unverified leads.

### Why Timeouts Are Not Vulnerabilities

A `--scan-mode full` scan or a low `--timeout` value may produce many INCONCLUSIVE findings on filtered or slow ports. This is expected behaviour; it does not mean those services are vulnerable. Increase `--timeout` and `--retries` and re-run the targeted check if you need a definitive answer.

---

## 📊 Report Formats

### JSON Report

The JSON report is written alongside the HTML report. Its top-level structure:

```json
{
  "target": "192.168.1.10",
  "timestamp": "2026-04-04T17:24:57.123456",
  "scanner_version": "4.0.0",
  "scan_mode": "common",
  "open_ports": [ ... ],
  "vulnerabilities": [ ... ],
  "nvd_intelligence": { ... },
  "compliance": { ... },
  "scan_metadata": {
    "scan_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "target": "192.168.1.10",
    "started": "2026-04-04T17:24:45.000000+00:00",
    "ended": "2026-04-04T17:24:57.000000+00:00",
    "config": { "timeout": 1.0, "retries": 1, "concurrency": 50, "mode": "common" }
  }
}
```

#### `open_ports` array

```json
{
  "port": 445,
  "state": "open",
  "service": "SMB",
  "banner": "Windows Server 2008 R2",
  "protocol": "tcp"
}
```

#### `vulnerabilities` array (one finding)

```json
{
  "id": "CVE-2017-0144",
  "cve": "CVE-2017-0144",
  "name": "EternalBlue",
  "title": "MS17-010 EternalBlue SMB Remote Code Execution",
  "severity": "CRITICAL",
  "status": "CONFIRMED",
  "port": 445,
  "affected_service": "SMB",
  "description": "SMBv1 is enabled and negotiation succeeded. The host may be susceptible to MS17-010.",
  "evidence": [
    "SMBv1 negotiate request returned a valid response",
    "Dialect: SMBv1 (0x0031)"
  ],
  "cisa_kev": true,
  "exploit_available": true,
  "cvss": 9.3,
  "remediation": "Disable SMBv1 and apply MS17-010 patch immediately.",
  "confidence": 0.9,
  "cve_refs": ["CVE-2017-0144"],
  "evidence_raw": null,
  "target": "192.168.1.10",
  "scan_timestamp": null
}
```

> **Phase A unified fields**: `confidence` (0.0–1.0), `cve_refs` (list of CVE IDs), `evidence_raw` (optional raw snippet), and `target` are added by the Phase A adapter and are present on every finding in the output.
```

#### `nvd_intelligence` object

```json
{
  "cve_count": 42,
  "query_date": "2026-04-04T17:24:57.000000+00:00",
  "lookback_days": 120
}
```

#### `compliance` object

```json
{
  "standard": "PCI DSS 3.2.1",
  "status": "FAIL",
  "score": 85,
  "issues": [
    "Critical unpatched vulnerability detected (CVE-2017-0144)"
  ]
}
```

### HTML Report

The HTML report is a self-contained file (no external dependencies) with the following sections:

1. **Executive summary** — Target, scan time, open port count, and confirmed vulnerability counts by severity.
2. **Open ports table** — Port, protocol, service name, and banner.
3. **Vulnerability findings** — One card per finding with status badge, severity, evidence list, CVSS score (where available), CISA KEV indicator, and remediation advice.
4. **Compliance results** — PCI DSS 3.2.1 pass/fail, score, and issue list.
5. **NVD enrichment summary** — Query date and number of CVEs retrieved.

---

## 💡 Examples

### Basic scan against a lab host

```bash
python3 vultron.py -t 10.0.0.5
```

### Full scan with increased concurrency and timeout

```bash
python3 vultron.py -t 10.0.0.5 --scan-mode full --concurrency 200 --timeout 2.0
```

### Target specific services only

```bash
python3 vultron.py -t 10.0.0.5 --scan-mode custom --ports 22,80,443,445,3389,3306
```

### Offline scan (no NVD, no compliance)

```bash
python3 vultron.py -t 10.0.0.5 --skip-nvd --skip-compliance
```

### Sample JSON finding (POTENTIAL status)

```json
{
  "id": "CVE-2019-0708",
  "cve": "CVE-2019-0708",
  "name": "BlueKeep",
  "title": "BlueKeep RDP Remote Code Execution",
  "severity": "HIGH",
  "status": "POTENTIAL",
  "port": 3389,
  "affected_service": "RDP",
  "description": "RDP port is exposed. BlueKeep (CVE-2019-0708) affects unpatched Windows systems. Patch status could not be verified remotely.",
  "evidence": [
    "Port 3389/tcp is open and accepting connections"
  ],
  "cisa_kev": true,
  "exploit_available": true,
  "cvss": 9.8,
  "remediation": "Apply Microsoft Security Update for CVE-2019-0708 and restrict RDP access using a VPN or firewall rule."
}
```

---

## 🔧 Troubleshooting

### NVD enrichment fails with status 404 or connection error

- The NVD API endpoint may be temporarily unavailable. Run again later, or use `--skip-nvd` to proceed without enrichment.
- If you are behind a corporate proxy, set the `HTTPS_PROXY` environment variable before running.
- Without an API key the rate limit is low (5 req/30 s). If you are running many scans, obtain and configure a free NVD key (see [Installation](#-installation)).

### Many INCONCLUSIVE results

- Increase `--timeout` (e.g., `--timeout 3.0`) and `--retries 2` to give slow hosts more time to respond.
- Firewall rules that silently drop packets will always produce INCONCLUSIVE; this is expected.

### Scan is slow on `--scan-mode full`

- Scanning all 65,535 ports takes significant time on slow networks. Raise `--concurrency` (e.g., `--concurrency 200`) to speed up the port discovery phase, but be aware that very high concurrency may exhaust file descriptors on some systems.
- Use `--scan-mode top1000` or a custom port list for a faster but still broad assessment.

### Permission errors (socket / raw socket)

- Vulntron uses plain TCP connect scans; no elevated privileges are required for port scanning or vulnerability checks.
- If you receive permission errors, verify your user account has network access to the target and that a local host firewall is not blocking outbound TCP connections.

### False positives / false negatives

- **False positives**: A CONFIRMED finding means Vulntron received an affirmative response from a probe. Before remediation, validate manually (e.g., verify SMBv1 is actually enabled with `Get-SmbServerConfiguration`).
- **False negatives**: A service might be running on a non-standard port not covered by your scan mode. Use `--scan-mode custom` with the specific port if you suspect this.

---

## 🛠️ Development

### Running Tests

```bash
python3 -m unittest tests/test_vultron.py -v
```

Test coverage includes:

- Scan mode port-list consistency (`TestScanModePortCoverage`)
- Port specification parsing (`TestParsePortSpec`)
- Summary counter accuracy (`TestCounterConsistency`)
- Timeout → INCONCLUSIVE conversion (`TestTimeoutInconclusiveHandling`)
- SMBGhost defensive classification (`TestSMBGhostNotAlwaysCritical`)
- NVD client response handling (`TestNVDClientResponseHandling`)
- BlueKeep status classification (`TestBlueKeepClassification`)
- FTP anonymous login outcomes (`TestFTPAnonymousCheck`)
- Telnet banner collection and timeout behavior (`TestTelnetBannerCheck`)
- SNMP default community check outcomes (`TestSNMPCommunityCheck`)
- CVE lookback days storage, defaults, and propagation (`TestCVELookbackDays`)
- **Phase A — Plugin registration and discovery** (`TestPhaseAPluginRegistration`)
- **Phase A — Finding schema serialisation and adapter** (`TestFindingSchema`)
- **Phase A — Pipeline emits unified findings** (`TestPipelineUnifiedFindings`)
- **Phase A — Reporter renders unified finding fields** (`TestReporterUnifiedFindings`)
- **Phase A — Built-in plugin checks** (`TestBuiltinPluginChecks`)
- **PR1 — Credential model validation** (`TestCredentialModelValidation`)
- **PR1 — Secret masking and redaction helpers** (`TestSecretMasking`)
- **PR1 — Credential providers** (`TestCredentialProviders`)
- **PR1 — Authenticated executor probes** (`TestAuthenticatedExecutor`)
- **PR1 — Auth probe plugin checks** (`TestAuthProbePluginChecks`)
- **PR1 — CLI credential argument parsing** (`TestCLICredentialParsing`)
- **PR1 — HybridScanner credentialed mode integration** (`TestHybridScannerCredentialedMode`)
- **PR1 — BaseCheck credential attributes** (`TestBaseCheckCredentialAttributes`)

### Syntax Check

```bash
python3 -c "import ast; ast.parse(open('vultron.py').read())"
```

### Code Style

- Follow [PEP 8](https://pep8.org/).
- Add type hints to new functions.
- Keep docstrings on public methods.

### Contributing

1. Fork the repository and create a feature branch: `git checkout -b feature/your-feature`.
2. Make your changes, add or update tests as appropriate.
3. Run the test suite and verify it passes.
4. Open a pull request with a clear description of what was changed and why.
5. PRs introducing new vulnerability checks must include at least one positive and one negative test case.

---

## ⚠️ Known Limitations

- **Best-effort scanning**: Vulntron uses TCP connect scans and application-layer probes. It is not a replacement for a full-featured scanner (e.g., Nessus, OpenVAS). Treat results as leads, not ground truth.
- **No UDP scanning**: The current implementation covers TCP only. Services running exclusively over UDP (e.g., DNS, SNMP, TFTP) will not be detected.
- **Version detection is limited**: Service versions are derived from banner strings only. Banners can be suppressed, customized, or spoofed by the target service.
- **Environment-dependent results**: Network topology, firewalls, load balancers, and IDS/IPS systems all affect what Vulntron can observe. Results are specific to the network path between the scanning host and the target.
- **NVD enrichment window**: CVE queries cover the last N days (default 120, configurable via `--cve-lookback-days`). Older CVEs are not fetched through the enrichment phase; known CVEs for specific checks (EternalBlue, SMBGhost, BlueKeep) are identified regardless.
- **Single target per run**: Each invocation scans one target. For subnet-wide assessments, script multiple invocations.

---

## 🗺️ Roadmap

- [ ] UDP port scanning support
- [ ] Multi-target / CIDR range input
- [ ] Service version correlation with CPE/NVD for more precise CVE matching
- [x] Additional protocol checks (FTP anonymous login, Telnet banner, SNMP default community)
- [x] Configurable CVE lookback period (`--cve-lookback-days`, default 120)
- [x] **Phase A: Plugin framework** — `plugins/` package, `BaseCheck` / `CheckRegistry`, 8 built-in checks
- [x] **Phase A: Unified finding schema** — `Finding`, `Evidence`, `ScanMetadata` dataclasses; adapter layer for backward compat
- [x] **PR1: Credentialed scanning framework** — SSH/WinRM/WMI credential model, secret redaction, provider abstraction, authenticated probes
- [ ] PR2: UDP scanner + service fingerprinting expansion
- [ ] PR3: SSL/TLS deep inspection module
- [ ] PR4: Asset inventory + host profiling
- [ ] PR5: Compliance engine (CIS/NIST/ISO policy packs)
- [ ] PR6: Patch detection (OS/package mapping via credentialed checks)
- [ ] PR7: Web application scanner (safe, non-exploit checks)
- [ ] PR8: Database security audits (read-only checks)
- [ ] PR9: Network device audits (Cisco/Juniper baseline)
- [ ] PR10: Cloud posture checks (AWS/Azure/GCP read-only)
- [ ] PR11: Scalable CVE check-pack architecture
- [ ] Phase C: Scheduled / continuous scanning
- [ ] Phase D: Web UI
- [ ] Machine-readable SARIF output for integration with GitHub Code Scanning
- [ ] Optional NVD API key injection via environment variable (`VULNTRON_NVD_KEY`)

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for full details.

```
MIT License

Copyright (c) 2025 Vultron Security Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### Author

**Azazi** — original author and maintainer.

### Acknowledgements

- [NIST NVD](https://nvd.nist.gov/) — CVE data and API
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — Known Exploited Vulnerabilities catalogue
- [Colorama](https://github.com/tartley/colorama), [Requests](https://requests.readthedocs.io/), [psutil](https://github.com/giampaolo/psutil) — Python dependencies

---

<div align="center">

**Vulntron** — *Defensive assessment tooling for authorized environments*

</div>
