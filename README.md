<div align="center">

# 🛡️ Vultron v2.1

### Enterprise-Grade Windows Security Auditor

*Comprehensive vulnerability scanning, digital forensics, and network analysis in a single tool*

[![Python Version](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-green.svg)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-Production%20Ready-success.svg)]()
[![Downloads](https://img.shields.io/badge/downloads-1K+-brightgreen.svg)]()

[Features](#-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Examples](#-examples) • [Contributing](#-contributing)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [What's New in v2.1](#-whats-new-in-v21)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Usage](#-usage)
- [Scan Modes](#-scan-modes)
- [Output](#-output)
- [Use Cases](#-use-cases)
- [Technical Details](#-technical-details)
- [Configuration](#-configuration)
- [Contributing](#-contributing)
- [License](#-license)
- [Acknowledgments](#-acknowledgments)

---

## 🎯 Overview

**Vultron** is a comprehensive Windows security auditing platform that combines vulnerability scanning, digital forensics, and network analysis into a single, easy-to-use tool. Built for security professionals, system administrators, and compliance officers.

### Why Vultron?

| Challenge | Vultron Solution |
|-----------|------------------|
| 🔍 **Finding old CVEs** | Scans complete history from 2015-present |
| 🔓 **Unknown network exposure** | Comprehensive port scanning with CVE correlation |
| 🕵️ **Limited forensic visibility** | 15+ artifact types for deep analysis |
| ⏱️ **Time-consuming manual work** | Automated one-click deployment |
| 📊 **Poor reporting** | Professional HTML + JSON reports |
| 💰 **Expensive tools** | 100% free and open source |

---

## ✨ Key Features

### 🔍 Vulnerability Scanning
- **Complete CVE Coverage**: Scans from 2015-present or last 120 days
- **NVD API 2.0 Integration**: Direct access to NIST vulnerability database
- **CISA KEV Detection**: Flags Known Exploited Vulnerabilities
- **Smart Matching**: Correlates CVEs with installed patches and services
- **CVSS Scoring**: Prioritizes by severity (Critical/High/Medium/Low)

### 🔓 Network Security Analysis
- **Port Scanning**: Comprehensive TCP/UDP listening port detection
- **Service Detection**: Identifies 25+ common services (SMB, RDP, SQL, etc.)
- **Version Extraction**: Attempts to determine service versions
- **CVE Correlation**: Maps specific CVEs to open ports
- **Risk Classification**: CRITICAL/HIGH/MEDIUM/LOW per port
- **External Exposure**: Flags internet-accessible services

### 🕵️ Digital Forensics
- **Persistence Mechanisms**: 9 registry locations + scheduled tasks
- **Execution Timeline**: Prefetch analysis (50 most recent)
- **Network Connections**: Active TCP connections with backdoor detection
- **PowerShell History**: Command analysis with malicious pattern detection
- **Event Logs**: System + Security log monitoring
- **USB History**: All connected storage devices
- **User Accounts**: Anomaly detection (hidden accounts, no passwords)
- **WMI Persistence**: Event subscription detection
- **Startup Analysis**: Both system and user startup folders

### 📊 Professional Reporting
- **Interactive HTML Dashboard**: Color-coded, executive-ready
- **JSON Export**: Machine-readable for automation
- **Risk Prioritization**: Critical findings highlighted
- **Detailed Findings**: CVE descriptions, CVSS scores, affected components
- **Forensic Analysis**: Suspicious items flagged automatically

---

## 🚀 What's New in v2.1

### Major Features

#### 🔓 Open Port Scanning & CVE Correlation
The biggest update! Vultron now scans your network attack surface.

```
✅ Detects all listening TCP/UDP ports
✅ Identifies services (SMB, RDP, SQL, HTTP, etc.)
✅ Extracts service versions
✅ Correlates CVEs to specific open ports
✅ Flags external exposure
✅ Built-in vulnerability database for 25+ services
```

**Example Output:**
```
[!] CRITICAL: Port 445/TCP (SMB) - System
    Known vulns: EternalBlue, SMBGhost, WannaCry
    CVE-2017-0144 affects this port (CVSS: 9.3)
    ⚠️ EXTERNAL ACCESS DETECTED
```

#### 🖥️ Command-Line Interface
```bash
python vultron_v2.py --help          # Show help
python vultron_v2.py --quick         # Fast scan (120 days)
python vultron_v2.py --comprehensive # Full scan (2015-present)
```

#### 📚 Built-in Help System
Complete documentation accessible via `--help` flag

[See Full Changelog](VERSION_2.1_CHANGELOG.md)

---

## ⚡ Quick Start

### Option 1: Automated (Recommended)

```batch
# 1. Download and extract Vultron
# 2. Right-click: setup.bat → Run as Administrator
# 3. Right-click: vultron_comprehensive.bat → Run as Administrator
# 4. Review the auto-opened HTML report
```

**That's it! 3 clicks to complete security audit.**

### Option 2: Manual

```bash
# Install dependencies
pip install colorama requests psutil

# Run scan
python vultron_v2.py

# View report
start vultron_report.html
```

---

## 📥 Installation

### Requirements
- **OS**: Windows 10 or Windows 11
- **Python**: 3.12 or higher
- **Privileges**: Administrator
- **Internet**: Required for NVD API access

### Method 1: Automated Setup

1. **Download** the latest release
2. **Extract** all files to a directory (e.g., `C:\Security\Vultron`)
3. **Run** `setup.bat` as Administrator
4. **Done!** Python and all dependencies installed automatically

### Method 2: Manual Setup

```bash
# Clone repository
git clone https://github.com/arazazi/vultron.git
cd vultron

# Install Python 3.12+ from python.org

# Install dependencies
pip install -r requirements.txt

# Verify installation
python vultron_v2.py --version
```

### Dependencies

```
colorama>=0.4.6    # Terminal colors
requests>=2.31.0   # NVD API access
psutil>=5.9.0      # System utilities (optional)
```

---

## 🎮 Usage

### Interactive Mode (Default)

```bash
python vultron_v2.py
```

You'll be prompted to select:
1. **Comprehensive** - Full CVE history (2015-present)
2. **Quick** - Last 120 days only

### Command-Line Mode

```bash
# Quick scan
python vultron_v2.py --quick

# Comprehensive scan
python vultron_v2.py --comprehensive

# Show help
python vultron_v2.py --help

# Show version
python vultron_v2.py --version
```

### Batch Files (Windows)

```batch
# One-time setup
setup.bat

# Full security audit
vultron_comprehensive.bat

# Fast security check
vultron_quick.bat
```

---

## 🔄 Scan Modes

### Comprehensive Mode (Recommended)

**Best for:** Old Windows 10 systems, thorough audits, compliance

```yaml
CVE Time Range: 2015 - Present
CVEs Scanned: 5,000 - 20,000+
Forensic Artifacts: 15+ types
Port Scanning: Full
Time: 3-5 minutes
```

**Perfect when:**
- System hasn't been regularly patched
- Running Windows 10 (any build from 2015+)
- Need complete vulnerability coverage
- Compliance or audit requirements
- Want to find historical vulnerabilities

### Quick Mode

**Best for:** Updated systems, regular monitoring

```yaml
CVE Time Range: Last 120 days
CVEs Scanned: 50 - 500
Forensic Artifacts: 15+ types (same)
Port Scanning: Full
Time: 1-2 minutes
```

**Perfect when:**
- System is regularly patched
- Running current Windows 11
- Quick security check needed
- Weekly/monthly monitoring
- Time-sensitive situations

---

## 📊 Output

### HTML Report (`vultron_report.html`)

<div align="center">


*Professional, interactive dashboard with color-coded findings*

</div>

**Features:**
- 📈 Executive metrics dashboard
- 🔴 Critical/High/Medium findings
- 🔓 Open ports with risk levels
- 🕵️ Forensic analysis results
- 📋 Detailed CVE descriptions
- 🎨 Color-coded severity levels
- 📱 Mobile-responsive design

### JSON Report (`vultron_report.json`)

Machine-readable format for automation and integration.

```json
{
  "metadata": {
    "scan_date": "2026-02-03T10:30:00",
    "scanner": "Vultron v2.1",
    "target_os": "Windows 11"
  },
  "inventory": { ... },
  "forensics": {
    "open_ports": [ ... ],
    "persistence": [ ... ],
    "execution_timeline": [ ... ]
  },
  "nvd_intelligence": {
    "vulnerabilities": [ ... ],
    "kev_vulns": [ ... ]
  },
  "audit_findings": {
    "critical": [ ... ],
    "port_vulnerabilities": [ ... ]
  }
}
```

---

## 💼 Use Cases

### 1. Security Audits
```yaml
Scenario: Monthly security assessment
Action: Run comprehensive scan
Result: Complete vulnerability inventory
Output: Professional report for management
```

### 2. Penetration Testing
```yaml
Scenario: Internal network assessment
Action: Port scan + CVE correlation
Result: Attack surface map with exploit paths
Output: Prioritized target list
```

### 3. Incident Response
```yaml
Scenario: Suspected compromise
Action: Full forensic scan
Result: IOCs, persistence mechanisms, timeline
Output: Detailed investigation report
```

### 4. Compliance
```yaml
Scenario: PCI-DSS/HIPAA audit
Action: Comprehensive scan + documentation
Result: Vulnerability + patch status
Output: Compliance evidence package
```

### 5. Legacy System Assessment
```yaml
Scenario: Old Windows Server 2012 R2
Action: Historical CVE scan (2015-present)
Result: All accumulated vulnerabilities
Output: Prioritized remediation plan
```

---

## 🔧 Technical Details

### Architecture

```
┌─────────────────────────────────────────────────┐
│            Vultron v2.1 Architecture            │
├─────────────────────────────────────────────────┤
│                                                 │
│  ┌─────────────┐  ┌─────────────┐             │
│  │  Module 1   │  │  Module 2   │             │
│  │ E-Inventory │  │  Forensics  │             │
│  └─────────────┘  └─────────────┘             │
│         │                │                      │
│         ├────────────────┴─────────┐           │
│         │                          │           │
│  ┌─────────────┐          ┌─────────────┐     │
│  │  Module 3   │          │  Module 4   │     │
│  │ NVD Intel   │──────────│    Audit    │     │
│  └─────────────┘          └─────────────┘     │
│         │                          │           │
│         └────────────┬─────────────┘           │
│                      │                         │
│              ┌─────────────┐                   │
│              │   Reports   │                   │
│              │  HTML/JSON  │                   │
│              └─────────────┘                   │
│                                                 │
└─────────────────────────────────────────────────┘
```

### Modules

#### Module 1: E-Inventory
- OS specifications via `platform` and WMI
- SBOM generation from Windows Registry
- Running services enumeration
- Installed patches (KB) listing

#### Module 2: Digital Forensics
- Registry persistence (9 locations)
- Scheduled tasks via PowerShell
- Network connections (Get-NetTCPConnection)
- **Port scanning (Get-NetTCPConnection/UDP)**
- **Service detection via WMI**
- PowerShell history analysis
- Prefetch timeline parsing
- Event log extraction
- USB device enumeration
- User account analysis

#### Module 3: NVD Intelligence
- NVD API 2.0 integration
- CPE 2.3 string generation
- Year-by-year CVE querying
- CISA KEV detection
- CVSS scoring

#### Module 4: Audit Engine
- Missing patch correlation
- Active service vulnerability matching
- **Port-to-CVE correlation**
- Risk prioritization algorithm

### Performance

```yaml
Port Scanning:      5-10 seconds
Service Detection:  10-15 seconds
CVE Query (Quick):  30-60 seconds
CVE Query (Full):   2-4 minutes
Forensic Analysis:  20-30 seconds
Report Generation:  5-10 seconds

Total (Quick):      1-2 minutes
Total (Comprehensive): 3-5 minutes
```

### Technology Stack

```
Language: Python 3.12+
APIs: NVD API 2.0
Frameworks: None (standard library + 3 deps)
Platform: Windows 10/11
Execution: PowerShell integration
Output: HTML5 + JSON
```

---

## ⚙️ Configuration

### NVD API Key (Optional)

For higher rate limits, add your NVD API key:

```python
# Edit vultron_v2.py line ~420
nvd = NVDIntelligence(api_key="YOUR_API_KEY_HERE")
```

Get a free API key: https://nvd.nist.gov/developers/request-an-api-key

**Benefits:**
- 50 requests per 30 seconds (vs 5 without key)
- Faster comprehensive scans
- More reliable during peak hours

### Customize Scan Parameters

```python
# Adjust CVE lookback period
nvd.query_nvd(days=90)  # Last 90 days instead of 120

# Change port scan timeout
PowerShellExecutor.execute(ps_cmd, timeout=90)  # 90 seconds

# Limit prefetch files
prefetch_files[:30]  # 30 instead of 50
```

---

---

## 🎓 Examples

### Example 1: Basic Scan

```bash
python vultron_v2.py
# Select: 1 (Comprehensive)
# Wait: 3-5 minutes
# Output: vultron_report.html opens automatically
```

### Example 2: Quick Check

```bash
python vultron_v2.py --quick
# Scan completes in 1-2 minutes
# Review critical findings only
```

### Example 3: Scheduled Audit

```batch
REM Create weekly scan task
schtasks /create /tn "Vultron Weekly" ^
  /tr "C:\Security\vultron_comprehensive.bat" ^
  /sc weekly /d MON /st 06:00 ^
  /ru SYSTEM /rl HIGHEST
```

### Example 4: Port Scan Only

```python
# Edit vultron_v2.py to run forensics only
forensics = DigitalForensics()
forensics.scan_open_ports()
```

### Example 5: Multiple Systems

```powershell
# Scan multiple computers
$computers = @("PC1", "PC2", "PC3")
foreach ($pc in $computers) {
    Invoke-Command -ComputerName $pc -ScriptBlock {
        python C:\Security\vultron_v2.py --comprehensive
    }
}
```

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### Ways to Contribute

- 🐛 **Report Bugs**: [Open an issue](https://github.com/arazazi/vultron/issues)
- 💡 **Suggest Features**: Share your ideas
- 📖 **Improve Docs**: Fix typos, add examples
- 🔧 **Submit Code**: Pull requests welcome!

### Development Setup

```bash
# Fork and clone
git clone https://github.com/arazazi/vultron.git
cd vultron

# Create branch
git checkout -b feature/your-feature

# Make changes and test
python vultron_v2.py --comprehensive

# Submit PR
git push origin feature/your-feature
```

### Coding Standards

- Follow PEP 8 style guide
- Add type hints for all functions
- Include docstrings
- Comment complex logic
- Test on Windows 10 and 11

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities.

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 Azazi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files...
```

---

## 🏆 Acknowledgments

### Special Thanks

- **NIST NVD**: For providing comprehensive CVE data
- **CISA**: For maintaining the KEV catalog
- **Microsoft**: For security bulletins and documentation
- **Security Community**: For feedback and testing

### Built With

- [Python](https://www.python.org/) - Programming language
- [Colorama](https://github.com/tartley/colorama) - Terminal colors
- [Requests](https://requests.readthedocs.io/) - HTTP library
- [psutil](https://github.com/giampaolo/psutil) - System utilities

### Inspiration

Built to solve real-world security challenges:
- Finding old CVEs on legacy Windows systems
- Automated port scanning with vulnerability correlation
- One-click security audits for compliance
- Professional reporting for executives

---

## 📊 Statistics

<div align="center">

![Lines of Code](https://img.shields.io/badge/lines_of_code-2640-blue)
![Functions](https://img.shields.io/badge/functions-45+-green)
![Modules](https://img.shields.io/badge/modules-4-orange)
![Forensic Artifacts](https://img.shields.io/badge/forensic_artifacts-15+-purple)

</div>

---


### FAQ

**Q: Do I need Python installed?**
A: No! Run `setup.bat` to install automatically.

**Q: Which scan mode should I use?**
A: Comprehensive for thorough audits, Quick for regular checks.

**Q: Is it safe to run in production?**
A: Yes! Read-only scanning, no system modifications.

**Q: How often should I scan?**
A: Weekly for production, monthly for workstations.

**Q: Can I scan remote systems?**
A: Yes, using PowerShell remoting (see examples).

---

## 🌟 Star History

<div align="center">

[![Star History Chart](https://api.star-history.com/svg?repos=arazazi/vultron&type=Date)](https://star-history.com/#arazazi/vultron&Date)

</div>

---

<div align="center">

## 🎯 Ready to Secure Your Infrastructure?

### [Download Now](https://github.com/arazazi/vultron/releases) • [View Docs](README.md) • [Report Issue](https://github.com/arazazi/vultron/issues)

**Made with ❤️ by the A. k Azazi**

---

⭐ **Star this repo** if you find it helpful!

🔔 **Watch** for updates and new releases

🍴 **Fork** to customize for your environment

---

**Vultron v2.1** - *Enterprise Security Made Simple*

</div>
