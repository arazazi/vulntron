<div align="center">

# 🛡️ Vulntron

### Defensive Vulnerability Assessment and Reporting Tool

*Authorized network vulnerability scanning with evidence-based findings and professional reporting*

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)]()
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-8.0.0-success.svg)]()

</div>

---

**Vulntron** is a defensive vulnerability assessment and reporting tool designed for use in authorized environments. It performs TCP and UDP port discovery, service fingerprinting with version hints and confidence scores, **SSL/TLS deep inspection**, **asset inventory with host profiling**, **baseline compliance & configuration posture checks**, **exposure & patch-risk detection**, targeted vulnerability checks with evidence, compliance assessment, CVE enrichment via the NVD API, and generates both HTML and JSON reports.

> **⚠️ Authorized use only.** Vulntron must only be run against systems you own or have explicit written permission to scan. See the [Safety, Ethics, and Authorization](#-safety-ethics-and-authorization) section.

---

## 📋 Table of Contents

1. [Features](#-features)
2. [Safety, Ethics, and Authorization](#-safety-ethics-and-authorization)
3. [Architecture Overview](#-architecture-overview)
4. [Credentialed Scanning](#-credentialed-scanning)
5. [UDP Scanning](#-udp-scanning)
6. [TLS Deep Inspection](#-tls-deep-inspection)
7. [Asset Inventory and Host Profiling](#-asset-inventory-and-host-profiling)
8. [Compliance & Configuration Baseline](#-compliance--configuration-baseline)
9. [Exposure & Patch Risk Detection](#-exposure--patch-risk-detection)
10. [Web Application Posture Scanner (P8)](#-web-application-posture-scanner-p8)
11. [Installation](#-installation)
12. [Quick Start](#-quick-start)
13. [CLI Reference](#-cli-reference)
14. [Understanding Results](#-understanding-results)
15. [Report Formats](#-report-formats)
16. [Examples](#-examples)
17. [Troubleshooting](#-troubleshooting)
18. [Development](#-development)
19. [Known Limitations](#-known-limitations)
20. [Roadmap](#-roadmap)
21. [License](#-license)

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

For each open port, Vulntron performs a banner-grab to identify the service and version string. Starting with v4.1, fingerprinting also assigns:

- **Normalised service name** — canonical representation (e.g., `HTTP`, `SSH`, `MySQL`).
- **Version hint** — extracted from banner when available (e.g., `OpenSSH_8.9p1`).
- **Confidence score** — float 0.0–1.0:
  - `0.9` — banner pattern matched (high confidence).
  - `0.5` — port-number lookup only (reasonable assumption).
  - `0.2` — no match found (identity uncertain).

Fingerprint data is included in the `fingerprint` field of each open-port record in the JSON report.

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

### 📋 Compliance & Configuration Baseline

Vulntron v7.0 introduces a **baseline compliance posture module** that evaluates the collected scan data against a set of non-invasive configuration controls.  Checks are grouped into named profiles (`baseline`, `server`, `workstation`) and produce per-control pass/fail/unknown/skip results with evidence.

Controls currently implemented:

| Control | Category | Description |
|---------|----------|-------------|
| TLS-001 | TLS | Deprecated TLS protocol (TLS 1.0 / 1.1) |
| TLS-002 | TLS | Certificate expiry within 30 days |
| TLS-003 | TLS | Expired certificate |
| TLS-004 | TLS | Self-signed / untrusted certificate chain |
| TLS-005 | TLS | Weak / deprecated cipher suite |
| SVC-001 | Services | Telnet (port 23) exposed |
| SVC-002 | Services | FTP (port 21) exposed |
| SVC-003 | Services | SNMP default community string accepted |
| SVC-004 | Services | High-risk legacy service port exposed |
| AUTH-001 | Auth | Anonymous FTP login accepted |
| AUTH-002 | Auth | Anonymous-access hint in banner |
| OS-001 | OS | OS patch posture (placeholder — credentialed only) |

### 🔍 Exposure & Patch Risk Detection

Vulntron v8.0 adds a **heuristic, non-intrusive exposure engine** (`plugins/exposure.py`) that derives patch-risk and exposure signals from scan data without any additional network probes.  Signal types include risky services, management interface exposure, weak TLS, certificate issues, EOL software versions, and database exposure.  All version-based signals are clearly labelled as heuristic with confidence scores.

### 🌐 Web Application Posture Scanner (P8)

Vulntron v8.0 adds an optional **safe, non-exploit web application scanner** (`plugins/web_scanner.py`) activated with `--web-scan`.  It performs read-only HTTP/HTTPS checks including security header analysis (CSP, HSTS, X-Frame-Options, etc.), cookie flag inspection, HTTP→HTTPS redirect verification, CORS misconfiguration heuristics, directory listing detection, robots.txt/sitemap presence, server banner disclosure, basic auth detection, and cache-control posture.  All authentication material is redacted from evidence before storage.

### 📦 Asset Inventory and Host Profiling

Vulntron v6.0 consolidates scan output into a normalised **asset inventory** (one record per scanned host).  Each record includes:

- Stable deterministic asset fingerprint for future diffing
- Resolved IP and hostname
- All open TCP/UDP services with banners and TLS posture
- OS hints extracted from service banners
- Aggregated vulnerability summary
- Inferred **host role** (`web-server`, `mail-server`, `dns-server`, etc.) with evidence
- Derived **risk level** (`critical`, `high`, `medium`, `low`, `none`)
- Human-readable **exposure summary**

The inventory is embedded in the JSON report and can optionally be saved as a standalone file (`--inventory-output`).

### 📄 HTML + JSON Reporting

- **HTML report**: A self-contained, color-coded dashboard with an executive summary, per-finding details, port table, compliance results, an **asset inventory section** (v6.0+), and an **Exposure & Patch Risk section** (v8.0+).
- **JSON report**: A machine-readable file covering all phases, suitable for ingestion by SIEMs, ticketing systems, or further automation.  Includes the `inventory` key with the full normalised asset snapshot and the `exposure` key with structured exposure signals.

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
User supplies target + options (--protocol tcp|udp|both)
         │
         ▼
┌───────────────────┐
│  PHASE 1          │  TCP connect scan (multi-threaded, configurable concurrency)
│  TCP Discovery    │  → Banner grabbing + service fingerprinting per open port
└────────┬──────────┘
         │  open ports + banners + fingerprints
         ▼
┌───────────────────┐
│  PHASE 1b         │  UDP probe scan (when --protocol udp|both)
│  UDP Discovery    │  → Protocol-aware probes: DNS, NTP, SNMP
│                   │  → State: open / open|filtered (no root required)
└────────┬──────────┘
         │  udp_ports: [{port, state, service, banner, protocol}, …]
         ▼
┌───────────────────┐
│  PHASE 1c         │  TLS deep inspection (auto-enabled for TLS-capable ports)
│  TLS Inspection   │  → Handshake metadata: protocol, cipher, ALPN, SNI
│                   │  → Certificate analysis: expiry, CN/SAN, self-signed, key size
│                   │  → Posture checks: legacy protocol, weak cipher, forward secrecy
└────────┬──────────┘
         │  tls_scan metadata + TLS findings (merged into vulnerabilities)
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
│  PHASE 3b         │  Asset inventory + host profiling (auto-enabled, --no-inventory to skip)
│  Asset Inventory  │  → Merges TCP/UDP/TLS/vuln data into one AssetRecord per host
│                   │  → HostProfiler: role inference, risk level, exposure summary
│                   │  → Optional standalone JSON snapshot (--inventory-output)
└────────┬──────────┘
         │  inventory snapshot (embedded in results)
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
├── udp_scanner.py    # UDPScanner: UDP engine, probe builders, state classification
├── fingerprint.py    # Service fingerprinting: banner parsing, normalisation, confidence
├── tls_inspector.py  # TLSInspector: TLS handshake inspection, cert/cipher analysis
├── inventory.py      # PR4: AssetRecord, InventoryBuilder, HostProfiler, persist_inventory
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

## 📡 UDP Scanning

> **⚠️ Authorized use only.** Only scan systems you own or have explicit written permission to test.

Vulntron v4.1 adds **UDP port discovery** via lightweight, non-intrusive probes. UDP scanning works without root/administrator privileges and does not require any additional dependencies.

### Protocol Selector

Use `--protocol` to choose the scan mode:

| Value | Behavior |
|-------|----------|
| `tcp` *(default)* | TCP connect scan only |
| `udp` | UDP probe scan only (no TCP) |
| `both` | TCP connect scan **and** UDP probe scan |

### UDP State Semantics

UDP scanning is inherently imprecise because many firewalls silently drop UDP packets. Vulntron uses a conservative three-state model:

| State | Meaning |
|-------|---------|
| `open` | A protocol-appropriate response was received — service is running |
| `open|filtered` | No response and no ICMP error — port may be open or filtered |
| *(excluded)* | ICMP port-unreachable received — port is definitively closed |

`open|filtered` is the most common result for filtered networks. Always verify with additional tools or network access before concluding a service is present.

### Protocol-Aware Probes

Vulntron sends a protocol-specific probe for known UDP services. All probes are **read-only** and **non-intrusive**:

| Port | Service | Probe |
|------|---------|-------|
| 53 | DNS | `version.bind` TXT/CH query |
| 123 | NTP | Mode 3 client request (48 bytes) |
| 161 / 162 | SNMP | SNMPv1 GetRequest for `sysDescr.0` |
| All others | — | Generic minimal datagram |

### Quick Start — UDP Scanning

**UDP-only scan (default UDP ports):**

```bash
python3 vultron.py -t 192.168.1.100 --protocol udp
```

**Combined TCP + UDP scan:**

```bash
python3 vultron.py -t 192.168.1.100 --protocol both
```

**UDP with custom timeout and retries:**

```bash
python3 vultron.py -t 192.168.1.100 --protocol udp --udp-timeout 3.0 --udp-retries 3
```

**UDP scan targeting specific ports:**

```bash
python3 vultron.py -t 192.168.1.100 --protocol udp --udp-ports 53,123,161,500,4500
```

**Combined scan, skip NVD (faster):**

```bash
python3 vultron.py -t 192.168.1.100 --protocol both --skip-nvd
```

### Default UDP Ports

When `--udp-ports` is not specified, Vulntron probes the following 16 common UDP services:

```
53 (DNS), 67 (DHCP), 69 (TFTP), 123 (NTP), 137 (NetBIOS-NS),
138 (NetBIOS-DGM), 161 (SNMP), 162 (SNMP-TRAP), 500 (IKE),
514 (Syslog), 520 (RIP), 1194 (OpenVPN), 1900 (SSDP),
4500 (IKE-NAT), 5353 (mDNS)
```

### UDP Scan Output

UDP results appear in a dedicated `udp_ports` section of the JSON report and as a separate table in the HTML report:

```json
{
  "udp_ports": [
    {"port": 53,  "state": "open",          "service": "DNS",  "banner": "", "protocol": "udp"},
    {"port": 161, "state": "open|filtered", "service": "SNMP", "banner": "", "protocol": "udp"}
  ]
}
```

### Caveats

- UDP scanning may generate a high volume of `open|filtered` results on heavily firewalled networks — this is expected and not an error.
- Raw-socket ICMP detection is not used; port-closed detection relies on `ConnectionRefusedError` from the OS, which may not always be surfaced.
- Concurrency is capped at 30 threads for UDP (regardless of `--concurrency`) to avoid overwhelming the target or local network stack.
- UDP scanning does **not** trigger vulnerability checks — the existing vulnerability checker runs only on TCP-discovered ports.

---

## 🔐 TLS Deep Inspection

> **⚠️ Authorized use only.** TLS inspection is a posture analysis technique, not a vulnerability exploit. Only run on systems you own or have explicit written permission to test.

Vulntron v5.0 adds **SSL/TLS deep inspection** via bounded, non-invasive TLS handshakes. The module performs **read-only handshake analysis** — it never injects data, exploits vulnerabilities, or alters server state.

### What is Inspected

TLS inspection runs automatically in **Phase 1c** immediately after TCP scanning, for any port carrying a TLS service.

| Check Category | Details |
|----------------|---------|
| **Protocol version** | Detects negotiated protocol; flags TLS 1.0 and TLS 1.1 as deprecated (RFC 8996) |
| **Legacy protocol support** | Probes for TLS 1.0/1.1 acceptance (best-effort, if OS allows) |
| **Cipher suite** | Flags NULL, EXPORT, anonymous (ADH/AECDH), RC4, RC2, 3DES, DES |
| **Forward secrecy** | Detects ECDHE/DHE key exchange; flags absence of forward secrecy |
| **Certificate expiry** | CRITICAL (\<7 days), HIGH (expired), MEDIUM (\<30 days) |
| **Certificate validity** | Flags not-yet-valid certificates |
| **Self-signed** | Flags certificates where issuer equals subject |
| **Untrusted chain** | Reports when system CA store cannot verify the chain |
| **Hostname mismatch** | Compares CN/SANs against target hostname (when not an IP) |
| **Weak signature algorithm** | Flags SHA-1 (HIGH) and MD5/MD2 (CRITICAL) when detectable |
| **Weak key size** | Flags RSA \< 2048-bit, EC/DSA \< 224-bit |
| **ALPN / SNI** | Captures negotiated ALPN protocol and SNI usage |

### TLS-Eligible Ports

TLS inspection is triggered for any TCP port that is:
- In the well-known TLS port set: `443, 465, 636, 853, 993, 995, 5986, 6443, 8443, ...`
- OR has a service name containing TLS-related keywords (`https`, `imaps`, `ldaps`, `smtps`, `tls`, etc.)

### Quick Start — TLS Inspection

TLS inspection runs automatically with a default TCP scan:

```bash
python3 vultron.py -t 192.168.1.100
# TLS inspection auto-runs for any open ports 443, 8443, 993, 995, 636, etc.
```

**Increase timeout for slow TLS stacks:**

```bash
python3 vultron.py -t 192.168.1.100 --tls-timeout 10.0
```

**Disable TLS inspection entirely:**

```bash
python3 vultron.py -t 192.168.1.100 --no-tls-inspect
```

**Combine with full TCP scan:**

```bash
python3 vultron.py -t 192.168.1.100 --scan-mode top1000 --tls-timeout 8.0 --tls-retries 2
```

### TLS Inspection Output

TLS results appear in a `tls_scan` section of the JSON report and as a dedicated table in the HTML report:

```json
{
  "tls_scan": {
    "443": {
      "host": "192.168.1.100",
      "port": 443,
      "protocol_version": "TLSv1.2",
      "protocol_display": "TLS 1.2",
      "cipher_name": "ECDHE-RSA-AES256-GCM-SHA384",
      "cipher_bits": 256,
      "has_forward_secrecy": true,
      "alpn": "h2",
      "sni_used": false,
      "cert_info": {
        "subject_cn": "example.com",
        "subject_san": ["example.com", "www.example.com"],
        "issuer_cn": "R3",
        "not_before": "2024-01-01T00:00:00+00:00",
        "not_after": "2025-01-01T00:00:00+00:00",
        "is_self_signed": false,
        "chain_trusted": true,
        "sig_algorithm": "sha256",
        "public_key_type": "RSA",
        "public_key_bits": 2048
      },
      "tls10_accepted": false,
      "tls11_accepted": false,
      "error": null,
      "duration_ms": 143.7
    }
  }
}
```

TLS-derived findings are merged into `results['vulnerabilities']` with `"category": "tls"` for unified reporting and severity counting.

### TLS Severity Model

| Severity | Condition |
|----------|-----------|
| CRITICAL | NULL cipher (no encryption) |
| HIGH     | Expired certificate, hostname mismatch, RC4/EXPORT/anonymous cipher, TLS 1.0/1.1 accepted, SHA-1/MD5 signature algorithm |
| MEDIUM   | Self-signed cert, untrusted chain, 3DES cipher, no forward secrecy, RSA \< 2048-bit key, cert expiring \< 30 days |

### Implementation Notes

- **Non-invasive**: Uses bounded TLS handshakes only; no exploit techniques.
- **Graceful failure**: All connection errors, SSL handshake failures, and timeouts are handled gracefully — the scan continues and the error is recorded in `tls_scan`.
- **Enhanced cert analysis**: When the `cryptography` library is installed (included by default in many Python environments), Vulntron extracts the certificate signature algorithm and public key size from the raw DER certificate. Without it, these fields are skipped.
- **Legacy protocol probing**: TLS 1.0/1.1 support is probed via separate handshake attempts with `minimum_version` pinned. If the local OpenSSL policy disallows these versions, the probe is skipped gracefully (reported as `null`).
- **Backward compatibility**: Disabling TLS inspection (`--no-tls-inspect`) or running UDP-only (`--protocol udp`) produces identical output to previous versions.

---

## 📦 Asset Inventory and Host Profiling

> **PR4 feature** — available in Vulntron v6.0.0+.

Vulntron v6.0 introduces a **first-class asset inventory subsystem** that consolidates all scan observations (TCP ports, UDP ports, TLS posture, vulnerability findings) into a stable, normalised asset record per host. The inventory is designed for reporting, tracking, and future compliance/patch workflows.

### What the Inventory Captures

For each scanned host, Vulntron produces a single `AssetRecord` containing:

| Field | Description |
|-------|-------------|
| `asset_id` | Stable 16-character hex fingerprint (SHA-256 of `<ip>\|<hostname>`) |
| `ip` | Primary IP address (resolved from target if a hostname) |
| `hostname` | FQDN / rDNS hostname, when available |
| `tcp_services` | Open TCP ports with service name, banner, version, and TLS posture |
| `udp_services` | Open UDP ports with service name and state |
| `os_hints` | OS/platform hints extracted from banners, with source and confidence |
| `vuln_summary` | Aggregated vulnerability counters (critical/high/medium/potential/KEV) |
| `risk_level` | Derived risk label: `critical`, `high`, `medium`, `low`, or `none` |
| `role` | Inferred host role: `web-server`, `mail-server`, `dns-server`, `file-server`, `database-server`, `network-device`, `workstation`, `legacy-device`, `server`, `unknown` |
| `role_evidence` | Ports/signals that led to the role inference |
| `exposure_summary` | One-line plain-text exposure description |
| `scan_sources` | Modules that contributed data (`tcp-scan`, `udp-scan`, `tls-inspect`) |
| `first_seen` / `last_seen` | Timestamps for first and most recent observation |

### Host Profiling Heuristics

Host profiling is performed by `HostProfiler` immediately after the inventory is built.  All heuristics are **deterministic and explainable** — the evidence used to derive each label is stored in `role_evidence`.

**Role inference** is based on recognisable open ports:

| Role | Trigger Ports |
|------|--------------|
| `mail-server` | 25, 110, 143, 465, 587, 993, 995 |
| `dns-server` | 53 (TCP or UDP) |
| `database-server` | 1433, 1521, 3306, 5432, 27017 |
| `network-device` | 161, 162 (SNMP) |
| `web-server` | 80, 443, 8080, 8443 |
| `file-server` | 139, 445 (SMB/Samba) |
| `workstation` | 3389 (RDP) |
| `legacy-device` | 23 (Telnet) |
| `server` | 22 (SSH only) |
| `unknown` | None of the above |

**Risk level** is derived from the vulnerability summary:

| Risk Level | Condition |
|------------|-----------|
| `critical` | At least one CONFIRMED CRITICAL finding |
| `high` | At least one CONFIRMED HIGH finding |
| `medium` | At least one CONFIRMED MEDIUM finding |
| `low` | Potential or inconclusive findings present |
| `none` | No findings |

### Quick Start — Asset Inventory

Asset inventory runs **automatically** by default alongside every scan.  No extra flags are required:

```bash
python3 vultron.py -t 192.168.1.100
# Inventory is built automatically and embedded in the JSON report.
```

**Save a standalone inventory JSON file:**

```bash
python3 vultron.py -t 192.168.1.100 --inventory-output inventory_192_168_1_100.json
```

**Disable inventory generation:**

```bash
python3 vultron.py -t 192.168.1.100 --no-inventory
```

### Inventory Output Format

The inventory is included in the `inventory` key of the main JSON report and optionally persisted as a standalone file via `--inventory-output`.  Both use the same schema:

```json
{
  "snapshot_id": "a1b2c3d4e5f6",
  "schema_version": "1.0",
  "generated_at": "2026-01-01T00:00:00+00:00",
  "asset_count": 1,
  "assets": [
    {
      "asset_id": "3f8a1b2c4d5e6f7a",
      "ip": "192.168.1.100",
      "hostname": "server.example.com",
      "os_hints": [
        { "hint": "SSH server (OpenSSH)", "source": "banner", "confidence": 0.4 }
      ],
      "tcp_services": {
        "22":  { "port": 22,  "protocol": "tcp", "service": "ssh",   "banner": "SSH-2.0-OpenSSH_8.9p1", "state": "open", "version": "OpenSSH_8.9p1" },
        "80":  { "port": 80,  "protocol": "tcp", "service": "http",  "banner": "Apache/2.4.54", "state": "open" },
        "443": { "port": 443, "protocol": "tcp", "service": "https", "state": "open",
                 "tls": { "port": 443, "protocol_version": "TLSv1.2", "cipher_name": "ECDHE-RSA-AES256-GCM-SHA384",
                          "cert_cn": "server.example.com", "has_forward_secrecy": true, "error": null } }
      },
      "udp_services": {
        "53": { "port": 53, "protocol": "udp", "service": "dns", "state": "open" }
      },
      "vuln_summary": {
        "total": 2, "critical_confirmed": 0, "high_confirmed": 1,
        "medium_confirmed": 0, "potential": 1, "inconclusive": 0, "kev_confirmed": 0
      },
      "risk_level": "high",
      "role": "web-server",
      "role_evidence": ["port 80/tcp open → web-server", "port 443/tcp open → web-server"],
      "exposure_summary": "3 TCP port(s) open; 1 UDP port(s) open/filtered; 1 TLS-capable port(s)",
      "first_seen": "2026-01-01T00:00:00",
      "last_seen": "2026-01-01T00:00:05+00:00",
      "scan_sources": ["tcp-scan", "tls-inspect", "udp-scan"]
    }
  ]
}
```

### HTML Report — Asset Inventory Section

When inventory data is present, the HTML report includes a dedicated **Asset Inventory** table showing:

- IP / host identifier
- Resolved hostname
- Inferred role
- Risk level badge
- TCP and UDP port counts
- Exposure summary

### Notes and Constraints

- **Single-host scope**: Each scan run targets one host and produces one asset record.  Multi-host aggregation across runs is planned for a future phase.
- **Discovery/posture oriented**: The inventory is designed for authorized discovery and posture assessment, not production asset management.
- **Stable fingerprint**: The `asset_id` is deterministic — repeated scans of the same host produce the same ID, enabling future diffing.

---

## 🛡 Compliance & Configuration Baseline

> **PR5 feature** — available in Vulntron v7.0.0+.

Vulntron v7.0 adds a **baseline compliance posture module** (`plugins/compliance.py`) that evaluates data collected by the scan phases against a curated set of safe, non-invasive configuration controls.  No additional network traffic is generated — all checks operate on data already gathered.

### Compliance Profiles

Controls are grouped into named profiles selectable via `--compliance-profile`:

| Profile | Intended Use | TLS Controls | Service Controls | Auth Controls | OS Controls |
|---------|-------------|:---:|:---:|:---:|:---:|
| `baseline` *(default)* | General assessment | ✅ | ✅ | ✅ | ✅ |
| `server` | Server-class targets | ✅ | ✅ | ✅ | ✅ |
| `workstation` | Workstation-class targets | ❌ | ✅ | ✅ | ✅ |

### Control Status Values

| Status | Meaning |
|--------|---------|
| `PASS` | Control evaluated and requirement is met |
| `FAIL` | Control evaluated and a problem was found (with evidence) |
| `UNKNOWN` | Insufficient data to determine compliance (e.g., no TLS data) |
| `SKIP` | Control explicitly skipped (e.g., credentials required but not provided) |

### Credential-Aware Controls

Controls that require authenticated access declare `requires_credentials: true`.  When credentials are absent or authentication did not succeed, these controls are automatically skipped with a clear reason:

| Control | Requires Credentials | Behaviour Without Creds |
|---------|---------------------|------------------------|
| OS-001  | Yes (placeholder) | Marked `SKIP` |

### Quick Start — Compliance

Run with the default `baseline` profile (compliance runs automatically alongside every scan):

```bash
python3 vultron.py -t 192.168.1.100
```

**Select a specific profile:**

```bash
python3 vultron.py -t 192.168.1.100 --compliance-profile server
python3 vultron.py -t 192.168.1.100 --compliance-profile workstation
```

**Show compliance-only console summary:**

```bash
python3 vultron.py -t 192.168.1.100 --compliance-only
```

**Disable compliance entirely:**

```bash
python3 vultron.py -t 192.168.1.100 --skip-compliance
```

**With credentialed access (enables OS-001):**

```bash
python3 vultron.py -t 192.168.1.100 --ssh-user scanuser --ssh-key /path/to/id_rsa --compliance-profile server
```

### Compliance Output

The compliance section is embedded in both the JSON report (under the `compliance` key) and rendered as a card in the HTML report with summary counts and detailed failed-control cards.

Console summary example:

```
[PHASE 3] COMPLIANCE ASSESSMENT
[*] Running compliance profile: baseline

[!] Compliance status: FAIL | pass=8 fail=2 skip/unknown=2
[!]   FAIL [HIGH] SVC-001: Telnet Service Exposed
[!]   FAIL [MEDIUM] SVC-002: FTP Service Exposed
```

### Limitations and Authorized Use

- Controls are **non-offensive** and **read-only** — they analyse already-collected data only.
- No full CIS or NIST framework mapping is included in this release.
- OS-001 is a placeholder; actual OS patch evaluation will require credentialed OS-level data in a future release.
- Only use Vulntron on systems you own or are explicitly authorized to assess.

---

## 🔍 Exposure & Patch Risk Detection

> **PR6 feature** — available in Vulntron v8.0.0+.

Vulntron v8.0 introduces a **patch and exposure detection engine** (`plugins/exposure.py`) that derives likely exposure and patch-risk signals by analysing data already gathered by earlier scan phases. **No additional network traffic is generated.**

> ⚠️ **Important:** All version-based signals are heuristic — they are derived from banner/version string pattern matching and may not reflect the actual patch level. Always verify signals manually before acting on them.

### How It Works

The exposure engine (`ExposureEngine`) ingests the full scan result dictionary and runs a series of non-intrusive detectors:

| Detector | Signal Type | Description |
|----------|-------------|-------------|
| Risky/cleartext service | `risky_service` | Open ports carrying dangerous legacy protocols (Telnet, FTP, r-commands, TFTP, etc.) |
| Management interface | `management_exposure` | Management services (RDP, WinRM, SSH, SNMP, Redis, MongoDB) accessible on default ports |
| SNMP default community | `unauthenticated_service` | SNMP default community string detected via compliance data or vulnerability findings |
| Weak TLS posture | `weak_tls` | Deprecated protocol version (TLS 1.0/1.1), weak/broken cipher, or missing forward secrecy |
| Certificate issues | `cert_issue` | Expired, near-expiry, or self-signed TLS certificates |
| EOL software version | `eol_version` *(heuristic)* | Service banner matches a curated table of known end-of-life version families |
| Anonymous service | `unauthenticated_service` | Anonymous or unauthenticated access confirmed by vulnerability/compliance findings |
| Database exposure | `database_exposure` | Database services (MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, etc.) on default ports |

### Signal Fields

Each exposure signal carries:

| Field | Type | Description |
|-------|------|-------------|
| `signal_id` | string | Unique signal identifier (e.g., `EXP-RISKY-SVC-001`) |
| `title` | string | Short descriptive title |
| `description` | string | Full description with remediation guidance |
| `evidence` | list | Specific evidence items supporting the signal |
| `confidence` | float | 0.0–1.0 confidence score |
| `confidence_label` | string | `HIGH` (≥0.75) / `MEDIUM` (0.45–0.74) / `LOW` (<0.45) |
| `severity` | string | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO` |
| `affected_asset` | string | Target host |
| `affected_service` | string | Service name (e.g., `FTP`, `TLS:443`) |
| `signal_type` | string | Detector category (e.g., `risky_service`, `eol_version`) |
| `heuristic` | bool | `true` when signal is version-pattern-based inference |

### EOL Version Heuristics

The engine includes a conservative curated table of end-of-life software version families:

| Pattern | Family | Recommended Minimum |
|---------|--------|---------------------|
| `OpenSSL/1.0.x` | OpenSSL 1.0.x | OpenSSL 1.1.1 or 3.x |
| `OpenSSL/1.1.0` | OpenSSL 1.1.0 | OpenSSL 1.1.1 or 3.x |
| `Apache/2.2.x` | Apache HTTPd 2.2.x | Apache 2.4.x |
| `Apache/2.0.x` | Apache HTTPd 2.0.x | Apache 2.4.x |
| `PHP/5.x` | PHP 5.x | PHP 8.x |
| `PHP/7.0.x`, `PHP/7.1.x` | PHP 7.0–7.1.x | PHP 8.x |
| `OpenSSH < 7.6` | OpenSSH (old) | OpenSSH 8.x+ |
| `nginx/1.0–1.12.x` | nginx (old) | nginx 1.18+ |
| `IIS/2–7.x` | IIS 7.x or older | IIS 10.x |
| `MySQL/4.x–5.x` | MySQL 4/5.x | MySQL 8.x |

> **No CVE database ingestion is performed.** These are conservative heuristics based on publicly known EOL dates, not real-time vulnerability data.

### Quick Start — Exposure Detection

Exposure detection runs **automatically** alongside every scan (enabled by default):

```bash
python3 vultron.py -t 192.168.1.100
```

**Disable exposure detection:**

```bash
python3 vultron.py -t 192.168.1.100 --no-exposure
```

**Enable additional lower-confidence heuristic signals (aggressive mode):**

```bash
python3 vultron.py -t 192.168.1.100 --exposure-aggressive
```

### Exposure Detection Output

Console example:

```
[PHASE 3c] EXPOSURE & PATCH-RISK DETECTION
Exposure signals: 5 total | critical=0 high=3 medium=2
  [HIGH] Risky service exposed: Telnet (port 23/tcp)
  [HIGH] Management interface exposed: RDP (port 3389/tcp)
  [MEDIUM] Potentially end-of-life software detected: Apache HTTPd 2.2.x (port 80/tcp) [heuristic]
```

The full exposure report is embedded in both the JSON report (`exposure` key) and rendered as an **"Exposure & Patch Risk"** section in the HTML report. Heuristic signals are clearly labelled in the HTML output.

### JSON Report Structure

```json
{
  "exposure": {
    "target": "192.168.1.100",
    "signal_count": 5,
    "summary": {
      "critical": 0,
      "high": 3,
      "medium": 2,
      "low": 0,
      "info": 0
    },
    "top_risks": [...],
    "signals": [
      {
        "signal_id": "EXP-RISKY-SVC-001",
        "title": "Risky service exposed: Telnet (port 23/tcp)",
        "description": "...",
        "evidence": ["Port 23/tcp is open", "Cleartext remote access"],
        "confidence": 0.85,
        "confidence_label": "HIGH",
        "severity": "HIGH",
        "affected_asset": "192.168.1.100",
        "affected_service": "Telnet",
        "signal_type": "risky_service",
        "heuristic": false
      }
    ]
  }
}
```

### Limitations and Design Constraints

- **No active exploitation.** The engine never sends probes or triggers additional connections.
- **No full CVE enrichment.** EOL version checks use a built-in curated table — not a live CVE feed.
- **Heuristic signals may produce false positives.** Version banners can be spoofed or customised; back-ported patches may address vulnerabilities in an older version string.
- **Confidence scores reflect signal reliability**, not exploitability.
- **Scope concept not implemented.** All detected services are evaluated uniformly. Future phases may add network scope/trust-zone awareness.
- The engine is designed to be **modular** for future enrichment phases (e.g., CVE correlation, CPE mapping).

---

## 🌐 Web Application Posture Scanner (P8)

> **P8 feature** — available in Vulntron v8.0.0+.

Vulntron v8.0 includes an optional **web application posture scanner** (`plugins/web_scanner.py`) that performs safe, non-exploit, non-destructive checks against HTTP/HTTPS services.  It is disabled by default and activated with `--web-scan`.

> ⚠️ **Safety guarantee:** The web scanner never sends exploit payloads, never attempts brute-force or credential stuffing, and never modifies server state.  All checks are read-only HTTP requests.

### How It Works

The web scanner discovers HTTP/HTTPS targets from open ports already found in the TCP scan phase (ports 80, 443, 8080, 8443, etc.) and optionally from user-supplied URLs (`--url` / `--urls-file`).  Each target is checked with a configurable concurrency limit to keep request volume low.

### Checks Performed

| Check | Finding ID | Severity |
|-------|------------|----------|
| Missing Content-Security-Policy | `WEB-HEADER-CSP` | MEDIUM |
| Missing HTTP Strict Transport Security | `WEB-HEADER-HSTS` | MEDIUM |
| Missing X-Frame-Options | `WEB-HEADER-XFO` | MEDIUM |
| Missing X-Content-Type-Options | `WEB-HEADER-XCTO` | MEDIUM |
| Missing Referrer-Policy | `WEB-HEADER-RP` | MEDIUM |
| Missing Permissions-Policy | `WEB-HEADER-PP` | MEDIUM |
| Permissive CSP (unsafe-inline / wildcard) | `WEB-HEADER-CSP-WEAK` | LOW |
| Cookie missing Secure / HttpOnly / SameSite | `WEB-COOKIE-FLAGS` | LOW |
| HTTP → HTTPS redirect absent | `WEB-REDIRECT-NO-HTTPS` | MEDIUM |
| CORS wildcard + credentials | `WEB-CORS-WILDCARD-CREDS` | MEDIUM |
| CORS reflected arbitrary origin | `WEB-CORS-REFLECT-ORIGIN` | MEDIUM |
| Directory listing (autoindex) heuristic | `WEB-DIRLIST` | LOW |
| robots.txt present (informational) | `WEB-ROBOTS-INFO` | INFO |
| sitemap.xml present (informational) | `WEB-SITEMAP-INFO` | INFO |
| Server/technology banner disclosed | `WEB-BANNER-INFO` | INFO |
| HTTP Basic Auth endpoint (HTTP cleartext) | `WEB-BASICAUTH-INFO` | MEDIUM/INFO |
| Cache-Control absent on sensitive paths | `WEB-CACHE-MISSING` | LOW |

### Evidence Redaction

All authentication material (cookies, `Set-Cookie` values, `Authorization`, `WWW-Authenticate`) is **redacted** before being stored in findings.  Raw auth tokens are never written to reports or logs.

### Quick Start — Web Scanner

```bash
# Enable web scanner for a target that has HTTP/HTTPS ports open
python3 vultron.py -t 192.168.1.100 --web-scan

# Add a specific URL (same host)
python3 vultron.py -t 192.168.1.100 --web-scan --url https://192.168.1.100:8443

# Read URLs from a file
python3 vultron.py -t 192.168.1.100 --web-scan --urls-file targets.txt

# Allow scanning URLs from different hosts (scope override)
python3 vultron.py -t 192.168.1.100 --web-scan \
    --url https://webapp.example.com \
    --web-allow-non-inventory-targets

# Custom concurrency and timeout
python3 vultron.py -t 192.168.1.100 --web-scan \
    --web-concurrency 3 --web-timeout 15

# Custom User-Agent
python3 vultron.py -t 192.168.1.100 --web-scan \
    --web-user-agent "InternalScanner/1.0 (authorized)"
```

### Web Scanner CLI Options

| Option | Default | Description |
|--------|---------|-------------|
| `--web-scan` | disabled | Enable web application posture scan |
| `--url URL` | — | Additional URL to scan |
| `--urls-file FILE` | — | Text file with URLs (one per line; `#` comments allowed) |
| `--web-concurrency N` | 5 | Maximum concurrent web check workers |
| `--web-timeout SECONDS` | 10.0 | Per-request HTTP timeout |
| `--web-max-paths N` | 3 | Maximum paths probed for directory-listing checks |
| `--web-user-agent UA` | built-in | Custom User-Agent for web requests |
| `--web-allow-non-inventory-targets` | false | Allow scanning URLs not matching the scan target host |
| `--web-auth-profile PROFILE` | — | Credential profile name for authenticated checks (still non-exploit) |

### Scope Controls

By default the web scanner only scans:
1. URLs derived from the TCP port scan (open web ports on the scan target), and
2. User-supplied `--url` / `--urls-file` entries whose hostname matches the scan target.

Use `--web-allow-non-inventory-targets` to scan out-of-scope user-supplied URLs.  Use this option only on systems you are authorised to test.

### JSON Report Structure

```json
{
  "web_posture": {
    "target_count": 2,
    "total_findings": 8,
    "summary": {
      "critical": 0,
      "high": 0,
      "medium": 4,
      "low": 2,
      "info": 2
    },
    "targets": [
      {
        "url": "http://192.168.1.100",
        "finding_count": 5,
        "error": null,
        "findings": [
          {
            "finding_id": "WEB-HEADER-CSP",
            "title": "Missing security header: Content-Security-Policy (CSP)",
            "description": "...",
            "severity": "MEDIUM",
            "confidence": 0.9,
            "confidence_label": "HIGH",
            "target_url": "http://192.168.1.100",
            "evidence": ["HTTP 200 from http://192.168.1.100/", "Header absent: Content-Security-Policy"],
            "remediation": "Configure your web server or application to set the Content-Security-Policy header in all responses."
          }
        ]
      }
    ]
  }
}
```

### Safety Notes

- **No exploit payloads** are ever sent.  Every request is a normal GET with a descriptive User-Agent.
- **No brute-force** login or credential stuffing.
- **Request volume is low** by design (configurable via `--web-concurrency` and `--web-max-paths`).
- The User-Agent identifies the scanner as an authorized security assessment tool.
- Cookie values are never stored in findings (redacted to `***REDACTED***`).
- Only use on systems and applications you are authorised to test.

---

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

Expected output: `Vultron 4.1.0`

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

### UDP Scanning Options (authorized use only)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--protocol` | choice | `tcp` | Scan protocol: `tcp`, `udp`, or `both` |
| `--udp-timeout` | float | `2.0` | Per-port UDP probe receive timeout in seconds |
| `--udp-retries` | int | `2` | Total UDP probe attempts per port (minimum 1) |
| `--udp-ports` | string | — | Custom UDP port list/ranges. Defaults to 16 common UDP service ports when not specified |

### TLS Deep Inspection Options (authorized use only)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--no-tls-inspect` | flag | `False` | Disable SSL/TLS deep inspection (enabled by default for TLS-capable ports) |
| `--tls-timeout` | float | `5.0` | Per-port TLS handshake timeout in seconds |
| `--tls-retries` | int | `2` | TLS handshake attempt count per port |

### Asset Inventory Options (PR4)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--no-inventory` | flag | `False` | Disable asset inventory generation (inventory is built by default) |
| `--inventory-output` | path | — | Save a standalone inventory JSON snapshot to this path (also embedded in main JSON report) |

### Compliance Options (PR5)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--skip-compliance` | flag | `False` | Skip all compliance checks |
| `--compliance-profile` | choice | `baseline` | Profile to run: `baseline`, `server`, or `workstation` |
| `--compliance-only` | flag | `False` | Print a compliance-only console summary after the scan |

### Exposure & Patch-Risk Detection Options (PR6)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--no-exposure` | flag | `False` | Disable exposure & patch-risk detection (enabled by default) |
| `--exposure-aggressive` | flag | `False` | Include additional lower-confidence heuristic signals |

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
  "profile": "baseline",
  "target": "192.168.1.100",
  "timestamp": "2026-04-11T10:00:00+00:00",
  "status": "FAIL",
  "issues": ["SVC-001: Telnet Service Exposed"],
  "summary": {
    "total": 12,
    "pass": 9,
    "fail": 1,
    "unknown": 2,
    "skip": 0
  },
  "controls": [
    {
      "control_id": "SVC-001",
      "title": "Telnet Service Exposed",
      "description": "Port 23/TCP (Telnet) is open...",
      "rationale": "Telnet provides no confidentiality...",
      "status": "FAIL",
      "severity": "HIGH",
      "evidence": ["Port 23/TCP (Telnet) is open and accessible"],
      "skip_reason": null,
      "requires_credentials": false
    }
  ]
}
```

### HTML Report

The HTML report is a self-contained file (no external dependencies) with the following sections:

1. **Executive summary** — Target, scan time, open port count, and confirmed vulnerability counts by severity.
2. **Open ports table** — Port, protocol, service name, and banner.
3. **Vulnerability findings** — One card per finding with status badge, severity, evidence list, CVSS score (where available), CISA KEV indicator, and remediation advice.
4. **Compliance posture** — Profile name, pass/fail/skip/unknown summary counts, and detailed failed-control cards with evidence.
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
- [x] **PR2: UDP scanner + service fingerprinting expansion** — protocol-aware probes (DNS/NTP/SNMP), state classification, service fingerprinting
- [x] **PR3: SSL/TLS deep inspection module** — cert analysis, cipher/protocol posture, legacy version detection, hostname mismatch
- [x] **PR4: Asset inventory + host profiling** — normalised asset records, deterministic fingerprint, host role/risk/exposure inference, JSON persistence
- [x] **PR5: Compliance & configuration baseline** — baseline posture controls (TLS, service exposure, auth), profile selection, credential-aware skip/unknown, HTML/JSON report integration
- [x] **PR6: Exposure & patch-risk detection** — heuristic, non-intrusive exposure signals (risky services, weak TLS, EOL versions, management exposure, database exposure, cert issues); confidence-graded; HTML/JSON report integration
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
