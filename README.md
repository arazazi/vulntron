# Vultron v2.0 - Windows Security Auditor

![Python](https://img.shields.io/badge/Python-3.12%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

A high-performance, single-file Windows security auditor combining **Vulnerability Scanning**, **Digital Forensics**, and **E-Inventory** capabilities.

## 🎯 Features

### Module 1: E-Inventory (Asset Discovery)
- **OS Specifications**: Build, Version, Architecture, MAC Address
- **SBOM Generation**: Complete software inventory from Windows Registry
- **Service Mapping**: All running services with executable paths
- **Patch Inventory**: List of installed Windows Updates (KBs)

### Module 2: Digital Forensics (Triage)
- **Persistence Check**: Registry Run Keys analysis
- **Execution Timeline**: 20 most recent programs from Prefetch
- **Event Log Monitoring**: Last 10 Critical/Error system events

### Module 3: NVD Intelligence (API 2.0)
- **CPE Builder**: Automatic CPE 2.3 string generation
- **Smart Queries**: 120-day vulnerability window
- **CISA KEV Detection**: Flags Known Exploited Vulnerabilities

### Module 4: Audit Engine & Logic Gates
- **Patch Matching**: Correlates CVEs with missing KBs
- **Active Risk Detection**: Running services with known vulnerabilities
- **Severity Scoring**: CVSS-based prioritization

## 📋 Requirements

### System Requirements
- **OS**: Windows 10 or Windows 11
- **Python**: 3.12 or higher
- **Privileges**: Administrator/Elevated

### Python Dependencies
```
colorama>=0.4.6
requests>=2.31.0
psutil>=5.9.0
```

Install dependencies:
```bash
pip install -r requirements.txt
```

## 🚀 Quick Start

### 1. Installation
```bash
# Clone or download vultron_v2.py
git clone <repository-url>
cd vultron

# Install dependencies
pip install -r requirements.txt
```

### 2. Running the Scan
```powershell
# Must run as Administrator
python vultron_v2.py
```

**Important**: Right-click PowerShell/Command Prompt → "Run as Administrator"

## 📊 Output

Vultron generates two comprehensive reports:

### 1. JSON Report (`vultron_report.json`)
Structured data containing:
- Complete system inventory
- Forensic findings
- NVD vulnerability data
- Audit results with severity levels

### 2. HTML Report (`vultron_report.html`)
Professional, interactive web report with:
- Executive dashboard
- Color-coded severity levels
- CISA KEV highlights
- Forensic analysis results
- System inventory summary

## 🎨 Terminal Output

```
[+] SECURE: OS Build 10.0.22631 is patched against KB5034441
[!] CRITICAL: Missing Patch for CVE-2024-1234 (CISA KEV!)
[?] FORENSIC: Suspicious Run Key found: C:\malware.exe
[!] ACTIVE RISK: Service 'Print Spooler' - CVE-2024-5678
```

## 🔧 Advanced Usage

### Custom NVD API Configuration
```python
# Edit the script to add your NVD API key for higher rate limits
nvd = NVDIntelligence(api_key="your_nvd_api_key_here")
```

Get your free API key from: https://nvd.nist.gov/developers/request-an-api-key

### Adjust Scan Parameters
```python
# Change the vulnerability lookback period (default: 120 days)
nvd.query_nvd(days=90)  # Last 90 days
```

## 🛡️ Security Features

### Logic Gates

**Gate 1: Missing Patch Detection**
```
IF (Version matches Vulnerable Range) 
AND (Required KB NOT in Patch List)
THEN Report CRITICAL
```

**Gate 2: Active Service Risk**
```
IF (Service is RUNNING) 
AND (Service has associated CVE)
THEN Report ACTIVE RISK
```

### CISA KEV Flagging
Vulnerabilities in CISA's Known Exploited Vulnerabilities catalog are automatically flagged with **IMMEDIATE ACTION REQUIRED**.

## 📁 Project Structure

```
vultron/
├── vultron_v2.py           # Main executable (single file)
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── vultron_report.json    # Generated JSON report
└── vultron_report.html    # Generated HTML report
```

## 🔍 Module Details

### PowerShell Executor
- Automatic execution policy bypass
- 30-second timeout protection
- Error handling and fallback
- Silent operation (no popup windows)

### Concurrent Processing
Uses Python's `ThreadPoolExecutor` to run:
- NVD API queries (non-blocking)
- Forensic analysis (parallel)
- Inventory collection (optimized)

### Error Handling
- Graceful degradation if optional libraries missing
- Registry access error recovery
- PowerShell execution failure handling
- API timeout management

## ⚠️ Common Issues

### Issue: "This script requires Administrator privileges"
**Solution**: Right-click your terminal → "Run as Administrator"

### Issue: "PowerShell execution policy error"
**Solution**: Script automatically uses `-ExecutionPolicy Bypass`

### Issue: "requests library not available"
**Solution**: 
```bash
pip install requests
```

### Issue: NVD API returns 403/429
**Solution**: 
- Wait 30 seconds between scans (rate limit)
- Add API key for higher limits
- Check internet connectivity

## 🎯 Use Cases

### Security Audits
- Regular vulnerability assessments
- Compliance scanning (PCI-DSS, HIPAA, SOC 2)
- Patch management verification

### Incident Response
- Post-compromise forensic triage
- Persistence mechanism detection
- Timeline reconstruction

### Asset Management
- Software inventory audits
- Service mapping
- Patch compliance reporting

## 📈 Performance

- **Scan Time**: 2-5 minutes (average)
- **API Calls**: 1-3 NVD requests
- **Memory Usage**: ~50-100 MB
- **CPU Usage**: Low (I/O bound)

## 🔐 Privacy & Security

- **No data collection**: All processing is local
- **No telemetry**: Results stay on your machine
- **No cloud dependencies**: Except NVD API (optional)
- **Read-only operations**: No system modifications

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional forensic artifacts
- More vulnerability sources
- Enhanced matching logic
- Performance optimizations

## 📝 License

MIT License - See LICENSE file for details

## 🙏 Acknowledgments

- **NVD (NIST)**: Vulnerability data source
- **CISA**: Known Exploited Vulnerabilities catalog
- **Microsoft**: Windows security documentation

## 📞 Support

For issues, questions, or feature requests:
1. Check the "Common Issues" section
2. Review the documentation
3. Open an issue on GitHub
4. Contact the security team

## 🔄 Version History

### v2.0 (Current)
- Complete rewrite in Python
- NVD API 2.0 integration
- CISA KEV detection
- Multi-threaded execution
- Professional HTML reports
- Enhanced forensics module

### v1.0 (Legacy)
- Initial release
- Basic vulnerability scanning

---

**⚠️ Disclaimer**: This tool is for authorized security testing only. Always obtain proper authorization before scanning systems you don't own.

**🛡️ Vultron v2.0** - Making Windows Security Audits Simple and Effective
