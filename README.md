<div align="center">

# 🛡️ Vulntron

### Defensive Vulnerability Assessment and Reporting Tool

*Authorized network vulnerability scanning with evidence-based findings and professional reporting*

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)]()
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-4.0.0--HYBRID-success.svg)]()

</div>

---

**Vulntron** is a defensive vulnerability assessment and reporting tool designed for use in authorized environments. It performs TCP port discovery, service fingerprinting, targeted vulnerability checks with evidence, compliance assessment, CVE enrichment via the NVD API, and generates both HTML and JSON reports.

> **⚠️ Authorized use only.** Vulntron must only be run against systems you own or have explicit written permission to scan. See the [Safety, Ethics, and Authorization](#-safety-ethics-and-authorization) section.

---

## 📋 Table of Contents

1. [Features](#-features)
2. [Safety, Ethics, and Authorization](#-safety-ethics-and-authorization)
3. [Architecture Overview](#-architecture-overview)
4. [Installation](#-installation)
5. [Quick Start](#-quick-start)
6. [CLI Reference](#-cli-reference)
7. [Understanding Results](#-understanding-results)
8. [Report Formats](#-report-formats)
9. [Examples](#-examples)
10. [Troubleshooting](#-troubleshooting)
11. [Development](#-development)
12. [Known Limitations](#-known-limitations)
13. [Roadmap](#-roadmap)
14. [License](#-license)

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

Vulntron queries the **NVD API 2.0** for CVEs published in the last 120 days. If the API is unreachable, rate-limited, or returns an error:

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
└────────┬──────────┘
         │  findings list
         ▼
┌───────────────────┐
│  PHASE 3          │  NVD API 2.0 query (last 120 days)
│  CVE Enrichment   │  → Retry / graceful fallback on API errors
└────────┬──────────┘
         │  enriched findings
         ▼
┌───────────────────┐
│  PHASE 4          │  PCI DSS 3.2.1 evaluation (optional, --skip-compliance)
│  Compliance       │  → Pass / Fail score + issue list
└────────┬──────────┘
         │  all results
         ▼
┌───────────────────┐
│  PHASE 5          │  HTML dashboard + JSON data file
│  Report Gen       │  → Saved to working directory
└───────────────────┘
```

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

Expected output: `Vultron 4.0.0-HYBRID`

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
| `--version` | flag | — | Show version string and exit |

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
  "scanner_version": "4.0.0-HYBRID",
  "scan_mode": "common",
  "open_ports": [ ... ],
  "vulnerabilities": [ ... ],
  "nvd_intelligence": { ... },
  "compliance": { ... }
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
  "remediation": "Disable SMBv1 and apply MS17-010 patch immediately."
}
```

#### `nvd_intelligence` object

```json
{
  "cve_count": 42,
  "query_date": "2026-04-04T17:24:57.000000"
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
- **NVD enrichment window**: CVE queries cover the last 120 days by default. Older CVEs are not fetched through the enrichment phase; known CVEs for specific checks (EternalBlue, SMBGhost, BlueKeep) are identified regardless.
- **Single target per run**: Each invocation scans one target. For subnet-wide assessments, script multiple invocations.

---

## 🗺️ Roadmap

- [ ] UDP port scanning support
- [ ] Multi-target / CIDR range input
- [ ] Service version correlation with CPE/NVD for more precise CVE matching
- [ ] Additional protocol checks (FTP anonymous login, Telnet banner, SNMP default community)
- [ ] Configurable CVE lookback period (currently fixed at 120 days)
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

**Abdul Raza** (MSc Cybersecurity) — original author and maintainer.

### Acknowledgements

- [NIST NVD](https://nvd.nist.gov/) — CVE data and API
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — Known Exploited Vulnerabilities catalogue
- [Colorama](https://github.com/tartley/colorama), [Requests](https://requests.readthedocs.io/), [psutil](https://github.com/giampaolo/psutil) — Python dependencies

---

<div align="center">

**Vulntron** — *Defensive assessment tooling for authorized environments*

</div>
