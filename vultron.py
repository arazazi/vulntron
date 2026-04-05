#!/usr/bin/env python3
"""
╦  ╦╦ ╦╦  ╔╦╗╦═╗╔═╗╔╗╔  ╦  ╦4.0
╚╗╔╝║ ║║   ║ ╠╦╝║ ║║║║  ╚╗╔╝
 ╚╝ ╚═╝╩═╝ ╩ ╩╚═╚═╝╝╚╝

Defensive vulnerability assessment and reporting tool for authorized environments.

Capabilities:
- TCP and UDP port discovery across configurable scan modes
- Service fingerprinting via banner collection with version hints and confidence scores
- Active vulnerability checks with evidence-based status (CONFIRMED / POTENTIAL / INCONCLUSIVE)
- Protocol checks: FTP anonymous login, Telnet banner, SNMP community strings
- UDP scanning with protocol-aware probes (DNS, NTP, SNMP) and state classification
- CVE enrichment via NVD API with configurable lookback window
- CISA Known Exploited Vulnerabilities (KEV) detection
- Compliance assessment (PCI DSS)
- HTML and JSON report generation

Author: Azazi
Version: 4.1.0
"""

import sys
import os
import socket
import argparse
import json
import struct
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Union

# Optional dependencies
try:
    import colorama
    from colorama import Fore, Style
    colorama.init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from concurrent.futures import ThreadPoolExecutor, as_completed
    HAS_THREADING = True
except ImportError:
    HAS_THREADING = False

# Plugin framework — graceful fallback when plugins/ is not importable
try:
    # Ensure the directory containing vultron.py is on sys.path so that the
    # ``plugins`` package can always be found regardless of the working directory.
    _SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    if _SCRIPT_DIR not in sys.path:
        sys.path.insert(0, _SCRIPT_DIR)

    import plugins.checks  # noqa: F401 — auto-registers all built-in checks
    from plugins import (
        CheckRegistry,
        Finding,
        ScanMetadata,
        CredentialSet,
        SSHCredential,
        WinRMCredential,
        WMICredential,
        build_default_provider,
        AuthenticatedExecutor,
    )
    from plugins.udp_scanner import UDPScanner, UDP_SERVICE_NAMES, UDP_DEFAULT_PORTS
    from plugins.fingerprint import fingerprint_banner, normalize_service_name, ServiceFingerprint
    _HAS_PLUGINS = True
except ImportError:
    _HAS_PLUGINS = False

# Configuration
NVD_API_KEY = "0cc77bb7-8bea-4758-ad90-b3ee02f8547b"  # Add your NVD API key here

VERSION = "4.1.0"
BANNER = f"""
{'='*90}
╦  ╦╦ ╦╦  ╔╦╗╦═╗╔═╗╔╗╔  ╦  ╦4.0
╚╗╔╝║ ║║   ║ ╠╦╝║ ║║║║  ╚╗╔╝
 ╚╝ ╚═╝╩═╝ ╩ ╩╚═╚═╝╝╚╝
{'='*90}
Version: {VERSION} | Author: Azazi
{'='*90}
"""

# Colors
class Colors:
    @staticmethod
    def critical(t): return f"{Fore.RED}{Style.BRIGHT}[CRITICAL] {t}{Style.RESET_ALL}" if HAS_COLORAMA else f"[CRITICAL] {t}"
    @staticmethod
    def high(t): return f"{Fore.YELLOW}{Style.BRIGHT}[HIGH] {t}{Style.RESET_ALL}" if HAS_COLORAMA else f"[HIGH] {t}"
    @staticmethod
    def medium(t): return f"{Fore.CYAN}[MEDIUM] {t}{Style.RESET_ALL}" if HAS_COLORAMA else f"[MEDIUM] {t}"
    @staticmethod
    def success(t): return f"{Fore.GREEN}✓ {t}{Style.RESET_ALL}" if HAS_COLORAMA else f"[+] {t}"
    @staticmethod
    def info(t): return f"{Fore.BLUE}[*] {t}{Style.RESET_ALL}" if HAS_COLORAMA else f"[*] {t}"
    @staticmethod
    def warning(t): return f"{Fore.YELLOW}[!] {t}{Style.RESET_ALL}" if HAS_COLORAMA else f"[!] {t}"
    @staticmethod
    def header(t): return f"{Fore.MAGENTA}{Style.BRIGHT}{t}{Style.RESET_ALL}" if HAS_COLORAMA else f"\n{'='*90}\n{t}\n{'='*90}"


class PortScanner:
    """Advanced port scanner with service detection and configurable scan modes"""

    COMMON_PORTS = {
        20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 80: 'HTTP', 110: 'POP3', 135: 'MS-RPC', 139: 'NetBIOS',
        143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 1433: 'MS-SQL', 3306: 'MySQL',
        3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
        8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
    }

    # Representative nmap top-1000 port list (includes high dynamic/RPC ports, WSD, etc.)
    TOP1000_PORTS = sorted(set([
        1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42,
        43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110,
        111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 163, 179, 199, 211, 212, 222,
        254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417,
        425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512, 513, 514, 515, 524,
        541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646,
        648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765,
        777, 783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911,
        912, 981, 987, 990, 992, 993, 995, 999, 1000, 1001, 1002, 1007, 1009, 1010, 1011,
        1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033,
        1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1044, 1048, 1049, 1050, 1053,
        1054, 1056, 1058, 1059, 1064, 1065, 1066, 1069, 1071, 1074, 1080, 1083, 1084,
        1085, 1088, 1090, 1092, 1095, 1099, 1100, 1102, 1104, 1105, 1106, 1107, 1108,
        1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1122, 1123, 1124, 1126, 1130,
        1131, 1132, 1137, 1138, 1141, 1145, 1147, 1148, 1149, 1151, 1152, 1154, 1163,
        1164, 1165, 1166, 1169, 1174, 1175, 1183, 1185, 1186, 1187, 1192, 1198, 1199,
        1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236, 1244, 1247, 1248, 1259, 1271,
        1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328, 1334, 1352,
        1417, 1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533,
        1556, 1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688, 1700, 1717, 1718,
        1719, 1720, 1721, 1723, 1755, 1761, 1782, 1783, 1801, 1805, 1812, 1839, 1840,
        1862, 1863, 1864, 1875, 1900, 1914, 1935, 1947, 1971, 1972, 1974, 1984, 1998,
        1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2013,
        2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045,
        2046, 2047, 2048, 2049, 2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111,
        2119, 2121, 2126, 2135, 2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196, 2200,
        2222, 2251, 2260, 2288, 2301, 2323, 2366, 2381, 2382, 2383, 2393, 2394, 2399,
        2401, 2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604, 2605, 2607, 2608, 2638,
        2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2910,
        2920, 2967, 2968, 2998, 3000, 3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017,
        3030, 3031, 3052, 3071, 3077, 3128, 3168, 3211, 3221, 3260, 3261, 3268, 3269,
        3283, 3300, 3301, 3306, 3322, 3323, 3324, 3325, 3333, 3351, 3367, 3369, 3370,
        3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517, 3527, 3546, 3551, 3580, 3659,
        3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827, 3828,
        3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986,
        3995, 3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126,
        4129, 4224, 4242, 4279, 4321, 4343, 4443, 4444, 4445, 4446, 4449, 4550, 4567,
        4662, 4848, 4899, 4900, 4998, 5000, 5001, 5002, 5003, 5004, 5009, 5030, 5033,
        5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100, 5101, 5102, 5120, 5190, 5200,
        5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431, 5432,
        5440, 5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633, 5666, 5678, 5679,
        5718, 5730, 5800, 5801, 5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862,
        5877, 5900, 5901, 5902, 5903, 5904, 5906, 5907, 5910, 5911, 5915, 5922, 5925,
        5950, 5952, 5959, 5960, 5961, 5962, 5963, 5987, 5988, 5989, 5998, 5999, 6000,
        6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106,
        6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547, 6565, 6566, 6567,
        6580, 6646, 6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792,
        6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004, 7007, 7019, 7025, 7070, 7100,
        7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496, 7512, 7625, 7627, 7676, 7741,
        7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000, 8001, 8002, 8007,
        8008, 8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083,
        8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192,
        8193, 8194, 8200, 8222, 8254, 8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402,
        8443, 8500, 8600, 8649, 8651, 8652, 8654, 8701, 8800, 8873, 8888, 8899, 8994,
        9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071, 9080, 9081, 9090,
        9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290, 9415,
        9418, 9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595, 9618, 9666, 9876,
        9877, 9878, 9898, 9900, 9917, 9929, 9943, 9944, 9968, 9998, 9999, 10000, 10001,
        10002, 10003, 10004, 10009, 10010, 10012, 10024, 10025, 10082, 10180, 10215,
        10243, 10566, 10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110, 11111,
        11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783, 14000, 14238,
        14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742, 16000, 16001, 16012,
        16016, 16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988,
        19101, 19283, 19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221,
        20222, 20828, 21571, 22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000,
        27352, 27353, 27355, 27356, 27715, 28201, 30000, 30718, 30951, 31038, 31337,
        32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778,
        32779, 32780, 32781, 32782, 32783, 32784, 32785, 33354, 33899, 34571, 34572,
        34573, 35500, 38292, 40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501,
        45100, 48080, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160,
        49161, 49163, 49165, 49167, 49175, 49176, 49400, 49999, 50000, 50001, 50002,
        50003, 50006, 50300, 50389, 50500, 50636, 50800, 51103, 51493, 52673, 52822,
        52848, 52869, 54045, 54328, 55055, 55056, 55555, 55600, 56737, 56738, 57294,
        57797, 58080, 60020, 60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000,
        65129, 65389,
    ]))

    # Service name lookup covering all known ports
    SERVICE_NAMES = {
        **{p: s for p, s in {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 135: 'MS-RPC', 139: 'NetBIOS',
            143: 'IMAP', 161: 'SNMP', 179: 'BGP', 389: 'LDAP', 443: 'HTTPS',
            444: 'SNPP', 445: 'SMB', 465: 'SMTPS', 500: 'IKE', 512: 'RSH',
            513: 'RLOGIN', 514: 'SYSLOG', 515: 'LPD', 554: 'RTSP', 587: 'SMTP-TLS',
            636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S', 1025: 'MS-RPC-DYN',
            1026: 'MS-RPC-DYN', 1027: 'MS-RPC-DYN', 1028: 'MS-RPC-DYN',
            1029: 'MS-RPC-DYN', 1030: 'MS-RPC-DYN', 1080: 'SOCKS',
            1433: 'MS-SQL', 1521: 'Oracle', 1723: 'PPTP', 1900: 'SSDP',
            2049: 'NFS', 3128: 'Squid-Proxy', 3306: 'MySQL', 3389: 'RDP',
            3690: 'SVN', 4444: 'Metasploit', 5357: 'WSD', 5432: 'PostgreSQL',
            5900: 'VNC', 5985: 'WinRM-HTTP', 5986: 'WinRM-HTTPS', 6379: 'Redis',
            6443: 'K8s-API', 7080: 'HTTP-Alt', 8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt', 8888: 'HTTP-Alt2', 9090: 'HTTP-Alt3',
            9200: 'Elasticsearch', 11211: 'Memcached', 27017: 'MongoDB',
            50000: 'SAP', 50070: 'Hadoop',
        }.items()},
    }

    def __init__(self, target: str, scan_mode: str = 'common',
                 custom_ports: Optional[List[int]] = None,
                 timeout: float = 1.0, retries: int = 1,
                 concurrency: int = 50):
        self.target = target
        self.scan_mode = scan_mode
        self.custom_ports = custom_ports or []
        self.timeout = timeout
        self.retries = retries
        self.concurrency = concurrency

    @staticmethod
    def parse_port_spec(spec: str) -> List[int]:
        """Parse a port specification string like '21,80,443,1025-1030' into a sorted list."""
        ports: List[int] = []
        for part in spec.split(','):
            part = part.strip()
            if '-' in part:
                lo, hi = part.split('-', 1)
                ports.extend(range(int(lo.strip()), int(hi.strip()) + 1))
            elif part.isdigit():
                ports.append(int(part))
        return sorted(set(p for p in ports if 1 <= p <= 65535))

    def get_ports_to_scan(self) -> List[int]:
        """Return the list of ports to scan based on the configured mode."""
        if self.scan_mode == 'full':
            return list(range(1, 65536))
        if self.scan_mode == 'top1000':
            return list(self.TOP1000_PORTS)
        if self.scan_mode == 'custom':
            return list(self.custom_ports) if self.custom_ports else list(self.COMMON_PORTS.keys())
        # default: 'common'
        return list(self.COMMON_PORTS.keys())

    def scan_port(self, port: int) -> Optional[Dict]:
        """Scan single port with banner grabbing and optional retries.

        ``self.retries`` is the total number of connection attempts (minimum 1).
        Each result is enriched with a :class:`ServiceFingerprint` summary.
        """
        for attempt in range(max(1, self.retries)):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target, port))

                if result == 0:
                    service = self.SERVICE_NAMES.get(port, f'Unknown-{port}')
                    banner = self.grab_banner(sock, port)
                    banner_str = banner[:100] if banner else ''

                    # Enrich with fingerprint data when the plugin layer is available
                    fp_dict: Optional[Dict] = None
                    if _HAS_PLUGINS:
                        fp = fingerprint_banner(banner_str, port, 'tcp', service)
                        fp_dict = fp.to_dict()

                    port_record: Dict = {
                        'port': port,
                        'state': 'open',
                        'service': service,
                        'banner': banner_str,
                        'protocol': 'tcp',
                    }
                    if fp_dict is not None:
                        port_record['fingerprint'] = fp_dict
                    return port_record

                sock.close()
                return None  # closed/filtered — no need to retry
            except Exception:
                if attempt < self.retries - 1:
                    continue
        return None

    def grab_banner(self, sock: socket.socket, port: int) -> str:
        """Grab service banner"""
        try:
            if port in [80, 8080]:
                sock.send(b'GET / HTTP/1.0\r\n\r\n')
            elif port == 21:
                pass  # FTP sends banner automatically
            else:
                sock.send(b'\r\n')

            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner
        except Exception:
            return ''

    def scan(self) -> List[Dict]:
        """Scan ports according to the configured mode and return open port results."""
        ports = self.get_ports_to_scan()
        mode_label = {
            'common': f"{len(ports)} common",
            'top1000': f"{len(ports)} top-1000",
            'full': "all 65535",
            'custom': f"{len(ports)} custom",
        }.get(self.scan_mode, str(len(ports)))
        print(Colors.info(f"Scanning {mode_label} ports on {self.target} "
                          f"(timeout={self.timeout}s, concurrency={self.concurrency})..."))

        results = []
        if HAS_THREADING:
            with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
                futures = {executor.submit(self.scan_port, port): port for port in ports}
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results.append(result)
                        print(Colors.success(f"  {result['port']}/tcp - {result['service']}"))
        else:
            for port in ports:
                result = self.scan_port(port)
                if result:
                    results.append(result)
                    print(Colors.success(f"  {result['port']}/tcp - {result['service']}"))

        results.sort(key=lambda r: r['port'])
        print(Colors.success(f"Found {len(results)} open ports\n"))
        return results

    def scan_common_ports(self) -> List[Dict]:
        """Backward-compatible alias: scan using the configured mode."""
        return self.scan()


class VulnerabilityChecker:
    """Vulnerability checking with defensive, evidence-based assessment

    Every finding includes a ``status`` field:
      CONFIRMED   – active probe returned definitive evidence.
      POTENTIAL   – port/service indicates possible exposure; version not verified.
      INCONCLUSIVE – check attempted but failed (timeout, network error, etc.).

    Only CONFIRMED findings are counted toward CRITICAL/HIGH severity totals.
    POTENTIAL and INCONCLUSIVE findings are surfaced separately so operators
    can investigate further without inflating the severity summary.
    """

    def __init__(self, target: str, ports: List[Dict]):
        self.target = target
        self.ports = ports
        self.vulnerabilities: List[Dict] = []

    # ------------------------------------------------------------------
    # Internal helper
    # ------------------------------------------------------------------

    def _add(self, finding: Dict):
        """Append a finding and echo a summary line to stdout."""
        self.vulnerabilities.append(finding)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def check_all(self) -> List[Dict]:
        """Run all vulnerability checks and return the findings list."""
        print(Colors.header("[PHASE 2] ACTIVE VULNERABILITY CHECKS"))
        print(Colors.info("Running exploitation tests...\n"))

        for port_info in self.ports:
            port = port_info['port']
            service = port_info['service']

            if port == 445:
                self.check_eternalblue(port)
                self.check_smbghost(port)
            elif port == 3389:
                self.check_bluekeep(port)
            elif port in [80, 443, 8080, 8443]:
                self.check_web_vulns(port)
            elif port in [3306, 5432, 1433, 27017, 6379]:
                self.check_database_vulns(port, service)
            elif port == 21 or service.upper() == 'FTP':
                self.check_ftp_anonymous(port)
            elif port == 23 or service.upper() == 'TELNET':
                self.check_telnet_banner(port)
            elif port == 161 or service.upper() == 'SNMP':
                self.check_snmp_community(port)

        confirmed = sum(1 for v in self.vulnerabilities if v.get('status') == 'CONFIRMED')
        potential = sum(1 for v in self.vulnerabilities if v.get('status') == 'POTENTIAL')
        inconclusive = sum(1 for v in self.vulnerabilities if v.get('status') == 'INCONCLUSIVE')
        print(Colors.success(
            f"\nChecks complete — {confirmed} confirmed, "
            f"{potential} potential, {inconclusive} inconclusive\n"
        ))
        return self.vulnerabilities

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def check_eternalblue(self, port: int):
        """Check for MS17-010 (EternalBlue) via SMBv1 negotiation probe."""
        print(Colors.info("  [SMB] Checking for EternalBlue (MS17-010)..."))
        evidence: List[str] = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, port))

            # Minimal SMBv1 negotiate request
            pkt = (
                b'\x00\x00\x00\x85'          # NetBIOS session
                b'\xff\x53\x4d\x42'          # SMB1 header magic
                b'\x72'                       # SMB_COM_NEGOTIATE
                b'\x00\x00\x00\x00\x00\x18\x53\xc8'
                b'\x00\x00\x00\x00\x00\x00\x00\x00'
                b'\x00\x00\x00\x00\x00\x00\xff\xfe'
                b'\x00\x00\x00\x00'
                b'\x00\x62'                   # ByteCount
                b'\x00\x02'
                b'\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00'  # NT LM 0.12
                b'\x02\x53\x4d\x42\x20\x32\x2e\x30\x30\x32\x00'  # SMB 2.002
                b'\x02\x53\x4d\x42\x20\x32\x2e\x3f\x3f\x3f\x00'  # SMB 2.???
            )
            sock.send(pkt)
            response = sock.recv(1024)
            sock.close()

            if b'\xff\x53\x4d\x42' in response:
                evidence.append("SMBv1 negotiate response received")
                evidence.append(f"Response bytes (hex): {response[:32].hex()}")
                self._add({
                    'id': 'MS17-010',
                    'cve': 'CVE-2017-0144',
                    'name': 'MS17-010 (EternalBlue)',
                    'title': 'EternalBlue SMBv1 Remote Code Execution',
                    'severity': 'CRITICAL',
                    'status': 'CONFIRMED',
                    'port': port,
                    'affected_service': 'SMB',
                    'description': ('SMBv1 is enabled and responded to a negotiate request. '
                                    'This version is susceptible to the EternalBlue exploit '
                                    '(MS17-010 / WannaCry / NotPetya).'),
                    'evidence': evidence,
                    'cisa_kev': True,
                    'exploit_available': True,
                    'cvss': 9.8,
                    'remediation': 'Disable SMBv1, apply MS17-010 patch',
                })
                print(Colors.critical("    CONFIRMED: SMBv1 negotiate accepted — EternalBlue risk!"))
            else:
                evidence.append("SMBv1 negotiate not accepted by server")
                print(Colors.success("    Not vulnerable (SMBv1 disabled or not negotiated)"))
        except socket.timeout:
            evidence.append("Connection timed out during SMB negotiate probe")
            self._add({
                'id': 'MS17-010',
                'cve': 'CVE-2017-0144',
                'name': 'MS17-010 (EternalBlue)',
                'title': 'EternalBlue SMBv1 — check inconclusive (timeout)',
                'severity': 'HIGH',
                'status': 'INCONCLUSIVE',
                'port': port,
                'affected_service': 'SMB',
                'description': ('EternalBlue check timed out. The port is open but the SMBv1 '
                                'probe did not receive a response. Manual verification required.'),
                'evidence': evidence,
                'cisa_kev': False,
                'exploit_available': False,
                'cvss': 9.8,
                'remediation': 'Disable SMBv1, apply MS17-010 patch; verify manually',
            })
            print(Colors.warning("    INCONCLUSIVE: check timed out — manual verification required"))
        except Exception as exc:
            evidence.append(f"Check failed: {exc}")
            self._add({
                'id': 'MS17-010',
                'cve': 'CVE-2017-0144',
                'name': 'MS17-010 (EternalBlue)',
                'title': 'EternalBlue SMBv1 — check inconclusive (error)',
                'severity': 'HIGH',
                'status': 'INCONCLUSIVE',
                'port': port,
                'affected_service': 'SMB',
                'description': f'EternalBlue check could not complete: {exc}',
                'evidence': evidence,
                'cisa_kev': False,
                'exploit_available': False,
                'cvss': 9.8,
                'remediation': 'Disable SMBv1, apply MS17-010 patch; verify manually',
            })
            print(Colors.warning(f"    INCONCLUSIVE: check error — {exc}"))

    def check_smbghost(self, port: int):
        """Check for SMBGhost (CVE-2020-0796) via SMBv3 compression capabilities probe."""
        print(Colors.info("  [SMB] Checking for SMBGhost (CVE-2020-0796)..."))
        evidence: List[str] = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, port))

            # Minimal SMBv3.1.1 negotiate request with compression capabilities context
            # (checks whether the server advertises SMB 3.1.1 + compression)
            pkt = (
                b'\x00\x00\x00\xc0'          # NetBIOS
                b'\xfeSMB'                   # SMB2 magic
                b'\x40\x00'                  # StructureSize
                b'\x00\x00'                  # CreditCharge
                b'\x00\x00\x00\x00'          # Status
                b'\x00\x00'                  # Command: Negotiate
                b'\x1f\x00'                  # CreditRequest
                b'\x00\x00\x00\x00'          # Flags
                b'\x00\x00\x00\x00'          # NextCommand
                b'\x00\x00\x00\x00\x00\x00\x00\x00'  # MessageId
                b'\x00\x00\x00\x00'          # Reserved
                b'\xff\xff\xff\xff'          # TreeId
                b'\x00\x00\x00\x00\x00\x00\x00\x00'  # SessionId
                b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Signature (part 1)
                b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Signature (part 2)
                # Negotiate body
                b'\x24\x00'                  # StructureSize
                b'\x08\x00'                  # DialectCount = 8
                b'\x02\x00'                  # SecurityMode
                b'\x00\x00'                  # Reserved
                b'\x7f\x00\x00\x00'          # Capabilities
                b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # ClientGuid
                b'\x78\x00'                  # NegotiateContextOffset (placeholder)
                b'\x02\x00'                  # NegotiateContextCount
                b'\x00\x00'                  # Reserved
                # Dialects
                b'\x02\x02'                  # SMB 2.0.2
                b'\x10\x02'                  # SMB 2.1
                b'\x00\x03'                  # SMB 3.0
                b'\x02\x03'                  # SMB 3.0.2
                b'\x10\x03'                  # SMB 3.1.1  ← key
                b'\x00\x03'
                b'\x02\x03'
                b'\x10\x03'
            )
            sock.send(pkt)
            response = sock.recv(1024)
            sock.close()

            smb2_magic = b'\xfeSMB'
            if smb2_magic in response:
                # Check for dialect 0x0311 in the response (SMB 3.1.1)
                smb311_confirmed = b'\x11\x03' in response
                evidence.append(f"SMBv2/3 negotiate response received (len={len(response)})")
                if smb311_confirmed:
                    evidence.append("Server advertised SMB dialect 3.1.1")
                    self._add({
                        'id': 'CVE-2020-0796',
                        'cve': 'CVE-2020-0796',
                        'name': 'SMBGhost (CVE-2020-0796)',
                        'title': 'SMBGhost — SMB 3.1.1 compression potential vulnerability',
                        'severity': 'HIGH',
                        'status': 'POTENTIAL',
                        'port': port,
                        'affected_service': 'SMB',
                        'description': ('Server negotiated SMB 3.1.1. CVE-2020-0796 (SMBGhost) '
                                        'affects Windows 10/Server 2019 without KB4551762. '
                                        'Confirm Windows build number to determine exposure.'),
                        'evidence': evidence,
                        'cisa_kev': False,
                        'exploit_available': True,
                        'cvss': 10.0,
                        'remediation': 'Apply KB4551762; disable SMBv3 compression if patch unavailable',
                    })
                    print(Colors.high("    POTENTIAL: SMB 3.1.1 detected — verify Windows build for CVE-2020-0796"))
                else:
                    evidence.append("SMB 3.1.1 not negotiated; SMBGhost unlikely")
                    print(Colors.success("    SMB 3.1.1 not negotiated; SMBGhost unlikely"))
            else:
                evidence.append("No SMB2/3 response received")
                print(Colors.success("    No SMBv2/3 response; SMBGhost not applicable"))
        except socket.timeout:
            evidence.append("Connection timed out during SMBGhost probe")
            self._add({
                'id': 'CVE-2020-0796',
                'cve': 'CVE-2020-0796',
                'name': 'SMBGhost (CVE-2020-0796)',
                'title': 'SMBGhost — check inconclusive (timeout)',
                'severity': 'HIGH',
                'status': 'INCONCLUSIVE',
                'port': port,
                'affected_service': 'SMB',
                'description': 'SMBGhost probe timed out. Manual version check required.',
                'evidence': evidence,
                'cisa_kev': False,
                'exploit_available': False,
                'cvss': 10.0,
                'remediation': 'Apply KB4551762; verify Windows build manually',
            })
            print(Colors.warning("    INCONCLUSIVE: SMBGhost check timed out"))
        except Exception as exc:
            evidence.append(f"Check error: {exc}")
            self._add({
                'id': 'CVE-2020-0796',
                'cve': 'CVE-2020-0796',
                'name': 'SMBGhost (CVE-2020-0796)',
                'title': 'SMBGhost — check inconclusive (error)',
                'severity': 'HIGH',
                'status': 'INCONCLUSIVE',
                'port': port,
                'affected_service': 'SMB',
                'description': f'SMBGhost check could not complete: {exc}',
                'evidence': evidence,
                'cisa_kev': False,
                'exploit_available': False,
                'cvss': 10.0,
                'remediation': 'Apply KB4551762; verify Windows build manually',
            })
            print(Colors.warning(f"    INCONCLUSIVE: SMBGhost check error — {exc}"))

    def check_bluekeep(self, port: int):
        """Check for BlueKeep (CVE-2019-0708) — RDP exposure assessment."""
        print(Colors.info("  [RDP] Checking for BlueKeep (CVE-2019-0708)..."))
        evidence: List[str] = [f"RDP port {port}/tcp is open"]
        # We can only confirm RDP is exposed; version/patch status needs OS-level data.
        self._add({
            'id': 'CVE-2019-0708',
            'cve': 'CVE-2019-0708',
            'name': 'BlueKeep (CVE-2019-0708)',
            'title': 'BlueKeep — RDP exposed, patch status unverified',
            'severity': 'HIGH',
            'status': 'POTENTIAL',
            'port': port,
            'affected_service': 'RDP',
            'description': ('RDP is exposed on this host. CVE-2019-0708 (BlueKeep) affects '
                            'unpatched Windows XP/2003/Vista/7/2008. Confirm Windows build '
                            'number to determine actual exposure.'),
            'evidence': evidence,
            'cisa_kev': True,
            'exploit_available': True,
            'cvss': 9.8,
            'remediation': 'Apply Windows security updates; enable Network Level Authentication',
        })
        print(Colors.high("    POTENTIAL: RDP exposed — verify patch level for BlueKeep"))
    
    def check_web_vulns(self, port: int):
        """Check web server vulnerabilities"""
        print(Colors.info(f"  [WEB] Checking port {port}..."))

        if not HAS_REQUESTS:
            print(Colors.warning("    Skipped (requests module not available)"))
            return

        try:
            protocol = 'https' if port in [443, 8443] else 'http'
            url = f"{protocol}://{self.target}:{port}"
            response = requests.get(url, verify=False, timeout=5)
            headers = response.headers
            evidence = [f"HTTP {response.status_code} from {url}"]

            missing = [h for h in ['X-Frame-Options', 'X-Content-Type-Options',
                                    'Strict-Transport-Security', 'Content-Security-Policy']
                       if h not in headers]
            if missing:
                evidence.extend(f"Missing header: {h}" for h in missing)
                self._add({
                    'id': f'WEB-HEADERS-{port}',
                    'cve': 'N/A',
                    'name': 'Missing Security Headers',
                    'title': f'Missing HTTP security headers on port {port}',
                    'severity': 'MEDIUM',
                    'status': 'CONFIRMED',
                    'port': port,
                    'affected_service': 'HTTP',
                    'description': f'One or more security response headers are absent: {", ".join(missing)}',
                    'evidence': evidence,
                    'remediation': 'Set X-Frame-Options, X-Content-Type-Options, HSTS, and CSP headers',
                })
                print(Colors.medium(f"    CONFIRMED: Security headers missing — {', '.join(missing)}"))
            else:
                print(Colors.success("    Security headers present"))
        except Exception:
            print(Colors.warning("    Unable to connect"))

    def check_database_vulns(self, port: int, service: str):
        """Check database vulnerabilities"""
        print(Colors.info(f"  [DATABASE] Checking {service}..."))
        self._add({
            'id': f'DB-EXPOSURE-{port}',
            'cve': 'N/A',
            'name': f'{service} Remote Access',
            'title': f'{service} database port {port} externally accessible',
            'severity': 'HIGH',
            'status': 'CONFIRMED',
            'port': port,
            'affected_service': service,
            'description': f'{service} is accessible from an external network on port {port}/tcp.',
            'evidence': [f'Port {port}/tcp ({service}) accepted TCP connection'],
            'remediation': 'Bind database to localhost only; restrict with firewall rules',
        })
        print(Colors.high(f"    CONFIRMED: {service} exposed externally!"))

    # ------------------------------------------------------------------
    # Protocol-specific checks
    # ------------------------------------------------------------------

    def check_ftp_anonymous(self, port: int):
        """Check whether the FTP server permits anonymous login."""
        print(Colors.info(f"  [FTP] Checking for anonymous login on port {port}..."))
        evidence: List[str] = [f"FTP port {port}/tcp is open"]
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, port))

            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            if banner:
                evidence.append(f"FTP banner: {banner[:100]}")

            sock.send(b'USER anonymous\r\n')
            user_resp = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            if user_resp:
                evidence.append(f"USER response: {user_resp[:80]}")

            # Some servers grant login on USER alone (230) or reject outright (530)
            if user_resp.startswith('230'):
                sock.close()
                self._add({
                    'id': f'FTP-ANON-{port}',
                    'cve': 'N/A',
                    'name': 'FTP Anonymous Login Enabled',
                    'title': f'FTP anonymous login accepted on port {port}',
                    'severity': 'HIGH',
                    'status': 'CONFIRMED',
                    'port': port,
                    'affected_service': 'FTP',
                    'description': ('The FTP server accepted anonymous login. '
                                    'Unauthenticated users may read or write files.'),
                    'evidence': evidence,
                    'remediation': 'Disable anonymous FTP access unless explicitly required.',
                })
                print(Colors.high("    CONFIRMED: FTP anonymous login accepted!"))
                return
            elif user_resp.startswith(('4', '5')):
                sock.close()
                evidence.append("Anonymous login rejected at USER stage")
                print(Colors.success("    NOT_AFFECTED: FTP anonymous login rejected"))
                return

            sock.send(b'PASS anonymous@example.com\r\n')
            pass_resp = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            if pass_resp:
                evidence.append(f"PASS response: {pass_resp[:80]}")
            sock.close()

            if pass_resp.startswith('230'):
                self._add({
                    'id': f'FTP-ANON-{port}',
                    'cve': 'N/A',
                    'name': 'FTP Anonymous Login Enabled',
                    'title': f'FTP anonymous login accepted on port {port}',
                    'severity': 'HIGH',
                    'status': 'CONFIRMED',
                    'port': port,
                    'affected_service': 'FTP',
                    'description': ('The FTP server accepted anonymous login. '
                                    'Unauthenticated users may read or write files.'),
                    'evidence': evidence,
                    'remediation': 'Disable anonymous FTP access unless explicitly required.',
                })
                print(Colors.high("    CONFIRMED: FTP anonymous login accepted!"))
            elif pass_resp.startswith(('3', '4', '5')):
                evidence.append("Anonymous login denied by server")
                print(Colors.success("    NOT_AFFECTED: FTP anonymous login denied"))
            else:
                self._add({
                    'id': f'FTP-ANON-{port}',
                    'cve': 'N/A',
                    'name': 'FTP Anonymous Login',
                    'title': f'FTP anonymous login result ambiguous on port {port}',
                    'severity': 'MEDIUM',
                    'status': 'POTENTIAL',
                    'port': port,
                    'affected_service': 'FTP',
                    'description': (f'FTP anonymous login result was ambiguous. '
                                    f'Response: {pass_resp[:50]}'),
                    'evidence': evidence,
                    'remediation': 'Review FTP server configuration for anonymous access settings.',
                })
                print(Colors.warning("    POTENTIAL: FTP anonymous login response ambiguous"))
        except socket.timeout:
            evidence.append("Connection timed out during FTP anonymous login check")
            self._add({
                'id': f'FTP-ANON-{port}',
                'cve': 'N/A',
                'name': 'FTP Anonymous Login',
                'title': f'FTP anonymous login check inconclusive (timeout) on port {port}',
                'severity': 'MEDIUM',
                'status': 'INCONCLUSIVE',
                'port': port,
                'affected_service': 'FTP',
                'description': 'FTP anonymous login check timed out. Manual verification required.',
                'evidence': evidence,
                'remediation': 'Verify FTP server anonymous access configuration manually.',
            })
            print(Colors.warning("    INCONCLUSIVE: FTP anonymous login check timed out"))
        except Exception as exc:
            evidence.append(f"Check error: {exc}")
            self._add({
                'id': f'FTP-ANON-{port}',
                'cve': 'N/A',
                'name': 'FTP Anonymous Login',
                'title': f'FTP anonymous login check inconclusive (error) on port {port}',
                'severity': 'MEDIUM',
                'status': 'INCONCLUSIVE',
                'port': port,
                'affected_service': 'FTP',
                'description': f'FTP anonymous login check could not complete: {exc}',
                'evidence': evidence,
                'remediation': 'Verify FTP server anonymous access configuration manually.',
            })
            print(Colors.warning(f"    INCONCLUSIVE: FTP check error — {exc}"))

    def check_telnet_banner(self, port: int):
        """Collect the Telnet banner and assess cleartext protocol exposure."""
        print(Colors.info(f"  [Telnet] Checking banner on port {port}..."))
        evidence: List[str] = [f"Telnet port {port}/tcp is open"]
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, port))

            raw = sock.recv(1024)
            sock.close()

            banner = raw.decode('utf-8', errors='ignore').strip()
            if banner:
                evidence.append(f"Telnet banner: {banner[:100]}")
            else:
                evidence.append("Connected but no banner text received")
            evidence.append("Telnet transmits all data (including credentials) in plaintext")

            self._add({
                'id': f'TELNET-EXPOSURE-{port}',
                'cve': 'N/A',
                'name': 'Telnet Service Exposed',
                'title': f'Telnet cleartext protocol exposed on port {port}',
                'severity': 'HIGH',
                'status': 'POTENTIAL',
                'port': port,
                'affected_service': 'Telnet',
                'description': ('Telnet is a legacy protocol that transmits all data, '
                                'including credentials, in cleartext. '
                                'Any network observer can intercept sessions.'),
                'evidence': evidence,
                'remediation': 'Disable Telnet; replace with SSH for encrypted remote access.',
            })
            print(Colors.high("    POTENTIAL: Telnet service exposed — unencrypted protocol"))
        except socket.timeout:
            evidence.append("Connection timed out during Telnet banner collection")
            self._add({
                'id': f'TELNET-EXPOSURE-{port}',
                'cve': 'N/A',
                'name': 'Telnet Service Exposed',
                'title': f'Telnet banner check inconclusive (timeout) on port {port}',
                'severity': 'MEDIUM',
                'status': 'INCONCLUSIVE',
                'port': port,
                'affected_service': 'Telnet',
                'description': ('Telnet banner collection timed out. '
                                'The service may be running but unresponsive.'),
                'evidence': evidence,
                'remediation': 'Disable Telnet; replace with SSH.',
            })
            print(Colors.warning("    INCONCLUSIVE: Telnet banner check timed out"))
        except Exception as exc:
            evidence.append(f"Check error: {exc}")
            self._add({
                'id': f'TELNET-EXPOSURE-{port}',
                'cve': 'N/A',
                'name': 'Telnet Service Exposed',
                'title': f'Telnet banner check inconclusive (error) on port {port}',
                'severity': 'MEDIUM',
                'status': 'INCONCLUSIVE',
                'port': port,
                'affected_service': 'Telnet',
                'description': f'Telnet banner check could not complete: {exc}',
                'evidence': evidence,
                'remediation': 'Disable Telnet; replace with SSH.',
            })
            print(Colors.warning(f"    INCONCLUSIVE: Telnet check error — {exc}"))

    @staticmethod
    def _build_snmp_getrequest(community: str, request_id: int = 0x1234) -> bytes:
        """Build a minimal SNMP v1 GetRequest PDU for sysDescr.0 (read-only probe)."""
        # OID 1.3.6.1.2.1.1.1.0 (sysDescr.0) encoded in BER
        oid_val = bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
        oid_tlv = bytes([0x06, len(oid_val)]) + oid_val
        null_tlv = bytes([0x05, 0x00])

        # varbind = SEQUENCE { oid, null }
        varbind_content = oid_tlv + null_tlv
        varbind = bytes([0x30, len(varbind_content)]) + varbind_content

        # varBindList = SEQUENCE { varbind }
        vbl = bytes([0x30, len(varbind)]) + varbind

        # GetRequest PDU (type 0xA0)
        req_id_val = struct.pack('>I', request_id)
        req_id_tlv = bytes([0x02, len(req_id_val)]) + req_id_val
        err_status = bytes([0x02, 0x01, 0x00])
        err_index = bytes([0x02, 0x01, 0x00])
        pdu_content = req_id_tlv + err_status + err_index + vbl
        pdu = bytes([0xA0, len(pdu_content)]) + pdu_content

        # Full SNMP message: SEQUENCE { version, community, pdu }
        version_tlv = bytes([0x02, 0x01, 0x00])
        comm_bytes = community.encode('ascii')
        comm_tlv = bytes([0x04, len(comm_bytes)]) + comm_bytes
        msg_content = version_tlv + comm_tlv + pdu
        return bytes([0x30, len(msg_content)]) + msg_content

    def check_snmp_community(self, port: int):
        """Check for default SNMP community strings via safe read-only UDP probe."""
        print(Colors.info(f"  [SNMP] Checking default community strings on port {port}/udp..."))
        evidence: List[str] = [f"SNMP port {port} detected"]
        communities = ['public', 'private']

        for community in communities:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                pkt = self._build_snmp_getrequest(community)
                sock.sendto(pkt, (self.target, port))
                response, _ = sock.recvfrom(1024)
                sock.close()

                evidence.append(
                    f"SNMP community '{community}' accepted "
                    f"({len(response)} bytes received)"
                )
                self._add({
                    'id': f'SNMP-DEFAULT-COMMUNITY-{port}',
                    'cve': 'N/A',
                    'name': 'SNMP Default Community String',
                    'title': f"SNMP default community '{community}' accepted on port {port}/udp",
                    'severity': 'HIGH',
                    'status': 'CONFIRMED',
                    'port': port,
                    'affected_service': 'SNMP',
                    'description': (
                        f"The SNMP agent accepted the default community string '{community}'. "
                        "This allows unauthenticated read access to device configuration "
                        "and network topology information."
                    ),
                    'evidence': evidence,
                    'remediation': (
                        'Change SNMP community strings from defaults; '
                        'upgrade to SNMPv3 with authentication and encryption; '
                        'restrict SNMP access via firewall rules.'
                    ),
                })
                print(Colors.high(f"    CONFIRMED: SNMP community '{community}' accepted!"))
                return
            except socket.timeout:
                evidence.append(f"SNMP community '{community}': no response (timeout)")
            except Exception as exc:
                evidence.append(f"SNMP community '{community}' check error: {exc}")

        # All communities timed out or errored — no definitive response
        self._add({
            'id': f'SNMP-DEFAULT-COMMUNITY-{port}',
            'cve': 'N/A',
            'name': 'SNMP Default Community String',
            'title': f'SNMP default community check inconclusive on port {port}/udp',
            'severity': 'MEDIUM',
            'status': 'INCONCLUSIVE',
            'port': port,
            'affected_service': 'SNMP',
            'description': (
                'SNMP default community probe received no response. '
                'The service may use non-default community strings or be filtered.'
            ),
            'evidence': evidence,
            'remediation': (
                'Use SNMPv3 with authentication and encryption; '
                'restrict SNMP access via firewall rules.'
            ),
        })
        print(Colors.warning("    INCONCLUSIVE: SNMP default community check received no response"))


class NVDIntelligence:
    """NVD CVE intelligence gathering with retry/backoff and graceful degradation"""

    # NVD 2.0 API requires ISO 8601 timestamps with explicit UTC offset
    _DATE_FMT = '%Y-%m-%dT%H:%M:%S.000 UTC+00:00'
    _MAX_RETRIES = 3
    _BACKOFF_BASE = 2  # seconds

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self._cache: Dict[str, Union[List[Dict], Optional[Dict]]] = {}

    def _get(self, params: Dict, attempt: int = 0) -> Optional[Dict]:
        """Perform a GET with retry/backoff; return parsed JSON or None."""
        if not HAS_REQUESTS:
            return None
        headers: Dict[str, str] = {}
        if self.api_key:
            headers['apiKey'] = self.api_key
        try:
            resp = requests.get(self.base_url, params=params, headers=headers, timeout=30)
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code in (403, 429, 503) and attempt < self._MAX_RETRIES:
                import time
                wait = self._BACKOFF_BASE ** attempt
                print(Colors.warning(f"  NVD API returned {resp.status_code}; retrying in {wait}s..."))
                time.sleep(wait)
                return self._get(params, attempt + 1)
            print(Colors.warning(f"NVD API returned status {resp.status_code} — enrichment skipped"))
            print(Colors.info(f"  Debug: URL={resp.url}"))
            return None
        except Exception as exc:
            if attempt < self._MAX_RETRIES:
                import time
                wait = self._BACKOFF_BASE ** attempt
                print(Colors.warning(f"  NVD request failed ({exc}); retrying in {wait}s..."))
                time.sleep(wait)
                return self._get(params, attempt + 1)
            print(Colors.warning(f"NVD query failed after {self._MAX_RETRIES} attempts: {exc}"))
            return None

    def query_recent_cves(self, days: int = 120) -> List[Dict]:
        """Query recent CVEs from NVD with correct date format and retries."""
        if not HAS_REQUESTS:
            print(Colors.warning("Skipping NVD query (requests not available)"))
            return []

        print(Colors.info(f"Querying NVD for CVEs from last {days} days..."))

        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)

        cache_key = f"recent_{days}_{start_date.date()}"
        if cache_key in self._cache:
            cached: List[Dict] = self._cache[cache_key]  # type: ignore[assignment]
            print(Colors.success(f"NVD: using cached result ({len(cached)} CVEs)"))
            return cached

        params = {
            'pubStartDate': start_date.strftime(self._DATE_FMT),
            'pubEndDate': end_date.strftime(self._DATE_FMT),
        }

        data = self._get(params)
        if data is None:
            return []

        cve_count = data.get('totalResults', 0)
        print(Colors.success(f"Retrieved {cve_count} CVEs from NVD"))
        result = data.get('vulnerabilities', [])
        self._cache[cache_key] = result
        return result

    def enrich_cve(self, cve_id: str) -> Optional[Dict]:
        """Look up a single CVE by ID; returns NVD data dict or None."""
        if not HAS_REQUESTS or not cve_id or cve_id == 'N/A':
            return None
        if cve_id in self._cache:
            cached_cve: Optional[Dict] = self._cache[cve_id]  # type: ignore[assignment]
            return cached_cve
        params = {'cveId': cve_id}
        data = self._get(params)
        if data:
            vulns = data.get('vulnerabilities', [])
            result: Optional[Dict] = vulns[0] if vulns else None
            self._cache[cve_id] = result
            return result
        return None


class ComplianceChecker:
    """Compliance assessment"""
    
    def __init__(self, scan_results: Dict):
        self.results = scan_results
    
    def check_pci_dss(self) -> Dict:
        """Check PCI DSS compliance"""
        print(Colors.header("[PHASE 3] COMPLIANCE ASSESSMENT"))
        print(Colors.info("Checking PCI DSS 3.2.1...\n"))

        issues = []

        # Check for insecure protocols
        if any(p['port'] == 23 for p in self.results.get('open_ports', [])):
            issues.append("Telnet (insecure protocol) detected")

        # Count only CONFIRMED critical findings to avoid false compliance failures
        critical_confirmed = [v for v in self.results.get('vulnerabilities', [])
                               if v.get('severity') == 'CRITICAL' and v.get('status') == 'CONFIRMED']
        if critical_confirmed:
            issues.append(f"{len(critical_confirmed)} confirmed critical vulnerabilities present")

        status = 'PASS' if not issues else 'FAIL'
        score = max(0, 100 - (len(issues) * 15))

        print(Colors.info(f"PCI DSS Status: {status}"))
        print(Colors.info(f"Compliance Score: {score}%"))
        print(Colors.info(f"Issues: {len(issues)}\n"))

        return {
            'standard': 'PCI DSS 3.2.1',
            'status': status,
            'score': score,
            'issues': issues
        }


class ReportGenerator:
    """Generate professional reports"""

    def __init__(self, scan_results: Dict):
        self.results = scan_results

    @staticmethod
    def _count_by_status_severity(vulns: List[Dict]) -> Dict:
        """Return a dict of counters derived solely from the findings list."""
        return {
            'critical_confirmed': sum(1 for v in vulns
                                      if v.get('severity') == 'CRITICAL' and v.get('status') == 'CONFIRMED'),
            'high_confirmed':     sum(1 for v in vulns
                                      if v.get('severity') == 'HIGH' and v.get('status') == 'CONFIRMED'),
            'medium_confirmed':   sum(1 for v in vulns
                                      if v.get('severity') == 'MEDIUM' and v.get('status') == 'CONFIRMED'),
            'potential':          sum(1 for v in vulns if v.get('status') == 'POTENTIAL'),
            'inconclusive':       sum(1 for v in vulns if v.get('status') == 'INCONCLUSIVE'),
            'kev_confirmed':      sum(1 for v in vulns if v.get('cisa_kev') and v.get('status') == 'CONFIRMED'),
        }

    def generate_html(self, filename: str):
        """Generate HTML assessment report"""
        print(Colors.info(f"Generating professional HTML report: {filename}"))

        target = self.results.get('target', 'Unknown')
        timestamp = self.results.get('timestamp', datetime.now().isoformat())
        open_ports = self.results.get('open_ports', [])
        udp_ports = self.results.get('udp_ports', [])
        vulns = self.results.get('vulnerabilities', [])
        compliance = self.results.get('compliance', {})
        scan_mode = self.results.get('scan_mode', 'common')
        scan_protocol = self.results.get('scan_protocol', 'tcp')
        cve_lookback_days = self.results.get('cve_lookback_days', 120)

        counts = self._count_by_status_severity(vulns)
        critical = counts['critical_confirmed']
        high = counts['high_confirmed']
        medium = counts['medium_confirmed']
        kev = counts['kev_confirmed']
        potential = counts['potential']
        inconclusive = counts['inconclusive']

        # Risk score based on confirmed findings only
        risk_score = min(10.0, (critical * 2.0) + (high * 1.0) + (medium * 0.3))

        confirmed_vulns = [v for v in vulns if v.get('status') == 'CONFIRMED']
        potential_vulns = [v for v in vulns if v.get('status') == 'POTENTIAL']
        inconclusive_vulns = [v for v in vulns if v.get('status') == 'INCONCLUSIVE']

        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vultron Security Platform - {target}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        :root {{
            --bg-primary: #0f1419;
            --bg-secondary: #1a1f28;
            --bg-card: #1e2430;
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --accent-orange: #f85149;
            --accent-yellow: #d29922;
            --border: #30363d;
        }}
        body {{
            font-family: 'Inter', -apple-system, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.5;
        }}
        .container {{ max-width: 1600px; margin: 0 auto; padding: 24px; }}
        .top-bar {{
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border);
            padding: 16px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
        }}
        .brand {{ display: flex; align-items: center; gap: 12px; }}
        .brand-logo {{
            width: 32px; height: 32px;
            background: linear-gradient(135deg, var(--accent-blue), var(--accent-green));
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
        }}
        .brand-name {{ font-size: 18px; font-weight: 600; }}
        .scan-info {{ display: flex; gap: 24px; font-size: 14px; color: var(--text-secondary); }}
        .status-dot {{
            width: 8px; height: 8px;
            background: var(--accent-green);
            border-radius: 50%;
            animation: pulse 2s infinite;
        }}
        @keyframes pulse {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.5; }} }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
        }}
        .stat-label {{
            font-size: 13px;
            color: var(--text-secondary);
            font-weight: 500;
            text-transform: uppercase;
            margin-bottom: 12px;
        }}
        .stat-value {{
            font-size: 36px;
            font-weight: 700;
            line-height: 1;
            margin-bottom: 4px;
        }}
        .stat-value.critical {{ color: var(--accent-orange); }}
        .stat-value.warning {{ color: var(--accent-yellow); }}
        .stat-value.info {{ color: var(--accent-blue); }}
        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 24px;
        }}
        .card-header {{ padding: 16px 20px; border-bottom: 1px solid var(--border); }}
        .card-title {{ font-size: 15px; font-weight: 600; }}
        .card-body {{ padding: 20px; }}
        .vuln-item {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 16px;
            margin-bottom: 12px;
        }}
        .vuln-header {{ display: flex; justify-content: space-between; margin-bottom: 8px; }}
        .vuln-cve {{ font-family: monospace; font-weight: 600; color: var(--accent-blue); }}
        .badge {{
            font-size: 11px;
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge-critical {{
            background: rgba(248, 81, 73, 0.2);
            color: var(--accent-orange);
            border: 1px solid rgba(248, 81, 73, 0.3);
        }}
        .badge-high {{
            background: rgba(210, 153, 34, 0.2);
            color: var(--accent-yellow);
            border: 1px solid rgba(210, 153, 34, 0.3);
        }}
        .badge-medium {{
            background: rgba(88, 166, 255, 0.2);
            color: var(--accent-blue);
            border: 1px solid rgba(88, 166, 255, 0.3);
        }}
        .badge-kev {{ background: linear-gradient(135deg, #f85149, #d73a49); color: white; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{
            text-align: left;
            padding: 12px 16px;
            font-size: 12px;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            border-bottom: 1px solid var(--border);
        }}
        td {{ padding: 14px 16px; font-size: 13px; border-bottom: 1px solid var(--border); }}
        tr:hover {{ background: rgba(88, 166, 255, 0.05); }}
        .footer {{
            text-align: center;
            padding: 24px;
            color: var(--text-secondary);
            border-top: 1px solid var(--border);
            margin-top: 24px;
        }}
    </style>
</head>
<body>
    <div class="top-bar">
        <div class="brand">
            <div class="brand-logo">V</div>
            <span class="brand-name">Vultron Security Platform</span>
        </div>
        <div class="scan-info">
            <span><span class="status-dot"></span> Scan Complete</span>
            <span>Target: {target}</span>
            <span>{timestamp[:19]}</span>
            <span>CVE Lookback: {cve_lookback_days}d</span>
        </div>
    </div>

    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Critical (confirmed)</div>
                <div class="stat-value critical">{critical}</div>
                <div style="font-size: 13px; color: var(--text-secondary);">Immediate action required</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">High (confirmed)</div>
                <div class="stat-value warning">{high}</div>
                <div style="font-size: 13px; color: var(--text-secondary);">Patch within 7 days</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Medium (confirmed)</div>
                <div class="stat-value info">{medium}</div>
                <div style="font-size: 13px; color: var(--text-secondary);">Patch within 30 days</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Potential</div>
                <div class="stat-value warning">{potential}</div>
                <div style="font-size: 13px; color: var(--text-secondary);">Needs verification</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Inconclusive</div>
                <div class="stat-value info">{inconclusive}</div>
                <div style="font-size: 13px; color: var(--text-secondary);">Manual review required</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">CISA KEV (confirmed)</div>
                <div class="stat-value critical">{kev}</div>
                <div style="font-size: 13px; color: var(--text-secondary);">Actively exploited</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Open TCP Ports</div>
                <div class="stat-value info">{len(open_ports)}</div>
                <div style="font-size: 13px; color: var(--text-secondary);">Scan mode: {scan_mode}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">UDP Ports</div>
                <div class="stat-value info">{len(udp_ports)}</div>
                <div style="font-size: 13px; color: var(--text-secondary);">open / open|filtered</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Risk Score</div>
                <div class="stat-value critical">{risk_score:.1f}</div>
                <div style="font-size: 13px; color: var(--text-secondary);">Out of 10 (confirmed only)</div>
            </div>
        </div>
'''

        # --- Confirmed findings section ---
        html += '''
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">🚨 Confirmed Findings</h3>
            </div>
            <div class="card-body">
'''
        if confirmed_vulns:
            for vuln in confirmed_vulns:
                sev = vuln.get('severity', 'MEDIUM').lower()
                kev_badge = '<span class="badge badge-kev">KEV</span>' if vuln.get('cisa_kev') else ''
                evidence_html = ''.join(
                    f'<li style="font-size:12px;color:var(--text-secondary);">{e}</li>'
                    for e in vuln.get('evidence', [])
                )
                html += f'''
                <div class="vuln-item">
                    <div class="vuln-header">
                        <span class="vuln-cve">{vuln.get('cve', 'N/A')}</span>
                        <div>
                            {kev_badge}
                            <span class="badge badge-{sev}">{vuln.get('severity', 'UNKNOWN')}</span>
                            <span class="badge" style="background:rgba(63,185,80,0.2);color:#3fb950;border:1px solid rgba(63,185,80,0.3);">CONFIRMED</span>
                        </div>
                    </div>
                    <div style="font-weight:500;margin-bottom:8px;">{vuln.get('title', vuln['name'])}</div>
                    <div style="color:var(--text-secondary);font-size:13px;margin-bottom:8px;">{vuln.get('description','')}</div>
                    <ul style="padding-left:16px;margin-bottom:8px;">{evidence_html}</ul>
                    <div style="font-size:12px;color:var(--text-secondary);">
                        🎯 CVSS {vuln.get('cvss','N/A')} | 🔌 Port {vuln.get('port','N/A')}/{vuln.get('protocol','tcp').upper()} |
                        ⚡ {'Exploit Available' if vuln.get('exploit_available') else 'No known exploit'} |
                        🛡 {vuln.get('affected_service','N/A')} |
                        📊 Confidence: {int(vuln.get('confidence', 0.9) * 100)}%
                    </div>
                </div>
'''
        else:
            html += '<div style="color:var(--text-secondary);">No confirmed findings</div>'

        html += '''
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <h3 class="card-title">⚠️ Potential Findings (verification required)</h3>
            </div>
            <div class="card-body">
'''
        if potential_vulns:
            for vuln in potential_vulns:
                sev = vuln.get('severity', 'HIGH').lower()
                evidence_html = ''.join(
                    f'<li style="font-size:12px;color:var(--text-secondary);">{e}</li>'
                    for e in vuln.get('evidence', [])
                )
                html += f'''
                <div class="vuln-item">
                    <div class="vuln-header">
                        <span class="vuln-cve">{vuln.get('cve', 'N/A')}</span>
                        <div>
                            <span class="badge badge-{sev}">{vuln.get('severity', 'UNKNOWN')}</span>
                            <span class="badge" style="background:rgba(210,153,34,0.2);color:#d29922;border:1px solid rgba(210,153,34,0.3);">POTENTIAL</span>
                        </div>
                    </div>
                    <div style="font-weight:500;margin-bottom:8px;">{vuln.get('title', vuln['name'])}</div>
                    <div style="color:var(--text-secondary);font-size:13px;margin-bottom:8px;">{vuln.get('description','')}</div>
                    <ul style="padding-left:16px;margin-bottom:8px;">{evidence_html}</ul>
                    <div style="font-size:12px;color:var(--text-secondary);">
                        🔌 Port {vuln.get('port','N/A')}/{vuln.get('protocol','tcp').upper()} | 🛡 {vuln.get('affected_service','N/A')} |
                        📊 Confidence: {int(vuln.get('confidence', 0.5) * 100)}%
                    </div>
                </div>
'''
        else:
            html += '<div style="color:var(--text-secondary);">No potential findings</div>'

        html += '''
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <h3 class="card-title">❓ Inconclusive Checks (manual review required)</h3>
            </div>
            <div class="card-body">
'''
        if inconclusive_vulns:
            for vuln in inconclusive_vulns:
                evidence_html = ''.join(
                    f'<li style="font-size:12px;color:var(--text-secondary);">{e}</li>'
                    for e in vuln.get('evidence', [])
                )
                html += f'''
                <div class="vuln-item">
                    <div class="vuln-header">
                        <span class="vuln-cve">{vuln.get('cve', 'N/A')}</span>
                        <span class="badge" style="background:rgba(139,148,158,0.2);color:#8b949e;border:1px solid rgba(139,148,158,0.3);">INCONCLUSIVE</span>
                    </div>
                    <div style="font-weight:500;margin-bottom:8px;">{vuln.get('title', vuln['name'])}</div>
                    <div style="color:var(--text-secondary);font-size:13px;margin-bottom:8px;">{vuln.get('description','')}</div>
                    <ul style="padding-left:16px;margin-bottom:8px;">{evidence_html}</ul>
                    <div style="font-size:12px;color:var(--text-secondary);">
                        🔌 Port {vuln.get('port','N/A')}/{vuln.get('protocol','tcp').upper()} | 🛡 {vuln.get('affected_service','N/A')} |
                        📊 Confidence: {int(vuln.get('confidence', 0.2) * 100)}%
                    </div>
                </div>
'''
        else:
            html += '<div style="color:var(--text-secondary);">No inconclusive checks</div>'

        html += '''
            </div>
        </div>
'''

        # --- TCP Open ports table ---
        if open_ports:
            html += '''
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">🔓 Open TCP Ports &amp; Services</h3>
            </div>
            <div class="card-body">
                <table>
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Service</th>
                            <th>State</th>
                            <th>Protocol</th>
                            <th>Version</th>
                            <th>Banner</th>
                        </tr>
                    </thead>
                    <tbody>
'''
            for port in open_ports:
                fp = port.get('fingerprint', {})
                version_hint = fp.get('version', '') or ''
                html += f'''
                        <tr>
                            <td><strong>{port['port']}</strong></td>
                            <td>{port['service']}</td>
                            <td>{port.get('state', 'open')}</td>
                            <td>{port['protocol']}</td>
                            <td style="font-size:12px;opacity:0.8;">{version_hint}</td>
                            <td style="font-family: monospace; font-size: 11px; opacity: 0.7;">{port.get('banner', '')[:50]}</td>
                        </tr>
'''
            html += '''
                    </tbody>
                </table>
            </div>
        </div>
'''

        # --- UDP ports table ---
        if udp_ports:
            html += '''
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">📡 UDP Ports &amp; Services</h3>
            </div>
            <div class="card-body">
                <table>
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Service</th>
                            <th>State</th>
                            <th>Protocol</th>
                            <th>Banner</th>
                        </tr>
                    </thead>
                    <tbody>
'''
            for port in udp_ports:
                state = port.get('state', 'open|filtered')
                state_color = '#3fb950' if state == 'open' else '#d29922'
                html += f'''
                        <tr>
                            <td><strong>{port['port']}</strong></td>
                            <td>{port['service']}</td>
                            <td style="color:{state_color};">{state}</td>
                            <td>udp</td>
                            <td style="font-family: monospace; font-size: 11px; opacity: 0.7;">{port.get('banner', '')[:50]}</td>
                        </tr>
'''
            html += '''
                    </tbody>
                </table>
            </div>
        </div>
'''

        # --- Compliance section ---
        if compliance:
            html += f'''
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">✓ Compliance Status</h3>
            </div>
            <div class="card-body">
                <table>
                    <thead>
                        <tr>
                            <th>Standard</th>
                            <th>Status</th>
                            <th>Score</th>
                            <th>Issues</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><strong>{compliance.get('standard', 'N/A')}</strong></td>
                            <td><span class="badge badge-{'critical' if compliance.get('status') == 'FAIL' else 'medium'}">{compliance.get('status', 'UNKNOWN')}</span></td>
                            <td>{compliance.get('score', 0)}%</td>
                            <td>{len(compliance.get('issues', []))}</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
'''

        html += f'''
        <div class="footer">
            <div style="font-size: 14px; margin-bottom: 8px;">Vultron v4.1 - Security Assessment</div>
            <div>Author: Azazi</div>
            <div style="margin-top: 12px; font-size: 13px; opacity: 0.7;">Report Generated: {timestamp[:19]}</div>
        </div>
    </div>
</body>
</html>'''

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)

        print(Colors.success(f"Professional HTML report saved: {filename}\n"))

    def generate_json(self, filename: str):
        """Generate JSON report with full structured findings."""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(Colors.success(f"JSON report saved: {filename}"))


class HybridScanner:
    """Main hybrid scanner combining all features"""

    def __init__(self, target: str, args):
        self.target = target
        self.args = args
        scan_mode = getattr(args, 'scan_mode', 'common')
        cve_lookback_days = getattr(args, 'cve_lookback_days', 120)
        scan_protocol = getattr(args, 'protocol', 'tcp')
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'scanner_version': VERSION,
            'scan_mode': scan_mode,
            'scan_protocol': scan_protocol,
            'cve_lookback_days': cve_lookback_days,
            'open_ports': [],
            'udp_ports': [],
            'vulnerabilities': [],
            'nvd_intelligence': {},
            'compliance': {},
            'auth_scan': {},
        }

    def _build_credential_set(self):
        """Build a CredentialSet from CLI args.  Returns None if not applicable."""
        if not _HAS_PLUGINS:
            return None
        args = self.args
        ssh_user = getattr(args, 'ssh_user', None)
        winrm_user = getattr(args, 'winrm_user', None)
        wmi_user = getattr(args, 'wmi_user', None)
        if not any([ssh_user, winrm_user, wmi_user]):
            return None

        ssh_cred = None
        if ssh_user:
            ssh_cred = SSHCredential(
                username=ssh_user,
                password=getattr(args, 'ssh_password', None) or None,
                key_path=getattr(args, 'ssh_key', None) or None,
                port=getattr(args, 'ssh_port', 22) or 22,
            )

        winrm_cred = None
        if winrm_user:
            winrm_transport = getattr(args, 'winrm_transport', 'http') or 'http'
            winrm_cred = WinRMCredential(
                username=winrm_user,
                password=getattr(args, 'winrm_password', None) or None,
                domain=getattr(args, 'winrm_domain', None) or None,
                transport=winrm_transport,
            )

        wmi_cred = None
        if wmi_user:
            wmi_cred = WMICredential(
                username=wmi_user,
                password=getattr(args, 'wmi_password', None) or None,
                domain=getattr(args, 'wmi_domain', None) or None,
            )

        return CredentialSet(ssh=ssh_cred, winrm=winrm_cred, wmi=wmi_cred)

    def run(self):
        """Execute full scan"""
        print(BANNER)
        print(Colors.header(f"[TARGET] {self.target}\n"))

        args = self.args
        scan_mode = getattr(args, 'scan_mode', 'common')
        scan_protocol = getattr(args, 'protocol', 'tcp')
        udp_timeout = getattr(args, 'udp_timeout', 2.0)
        udp_retries = getattr(args, 'udp_retries', 2)
        udp_ports_arg = getattr(args, 'udp_ports', None)

        # Build credential set from CLI args (if any)
        credential_set = self._build_credential_set()
        credentialed_mode = credential_set is not None and not credential_set.is_empty()

        # Capture scan start time for metadata
        if _HAS_PLUGINS:
            _scan_meta = ScanMetadata.new(
                self.target,
                config={
                    'timeout': getattr(args, 'timeout', 1.0),
                    'retries': getattr(args, 'retries', 1),
                    'concurrency': getattr(args, 'concurrency', 50),
                    'mode': scan_mode,
                    'protocol': scan_protocol,
                    'udp_timeout': udp_timeout,
                    'udp_retries': udp_retries,
                    'credentialed': credentialed_mode,
                },
            )

        # Phase 1: TCP Port Scanning (skipped when protocol=udp)
        if scan_protocol in ('tcp', 'both'):
            print(Colors.header("[PHASE 1] TCP PORT SCANNING"))
            custom_ports: List[int] = []
            if scan_mode == 'custom' and getattr(args, 'ports', None):
                custom_ports = PortScanner.parse_port_spec(args.ports)

            scanner = PortScanner(
                self.target,
                scan_mode=scan_mode,
                custom_ports=custom_ports,
                timeout=getattr(args, 'timeout', 1.0),
                retries=getattr(args, 'retries', 1),
                concurrency=getattr(args, 'concurrency', 50),
            )
            self.results['open_ports'] = scanner.scan()
        else:
            print(Colors.info("TCP scanning skipped (protocol=udp)"))

        # Phase 1b: UDP Port Scanning (when protocol=udp or both)
        if scan_protocol in ('udp', 'both') and _HAS_PLUGINS:
            print(Colors.header("[PHASE 1b] UDP PORT SCANNING"))
            udp_port_list: Optional[List[int]] = None
            if udp_ports_arg:
                udp_port_list = PortScanner.parse_port_spec(udp_ports_arg)

            udp_scanner = UDPScanner(
                target=self.target,
                ports=udp_port_list,
                timeout=udp_timeout,
                retries=udp_retries,
                concurrency=min(getattr(args, 'concurrency', 50), 30),
            )
            print(Colors.info(
                f"Scanning {len(udp_scanner.ports)} UDP ports on {self.target} "
                f"(timeout={udp_timeout}s, retries={udp_retries})..."
            ))
            udp_results = udp_scanner.scan()
            self.results['udp_ports'] = udp_results
            for r in udp_results:
                state_label = r['state']
                print(Colors.success(
                    f"  {r['port']}/udp - {r['service']} [{state_label}]"
                ))
            print(Colors.success(f"Found {len(udp_results)} UDP ports (open/open|filtered)\n"))

        # Require at least one open TCP port for vulnerability checks
        if not self.results['open_ports'] and scan_protocol in ('tcp', 'both'):
            print(Colors.warning("No open TCP ports found!"))
            if _HAS_PLUGINS:
                _scan_meta.ended = datetime.now(timezone.utc).isoformat()
                self.results['scan_metadata'] = _scan_meta.to_dict()
            if not self.results.get('udp_ports'):
                return

        # [PHASE 2] Vulnerability Checks — TCP only (legacy VulnerabilityChecker path)
        if self.results['open_ports']:
            vuln_checker = VulnerabilityChecker(self.target, self.results['open_ports'])
            legacy_findings = vuln_checker.check_all()
        else:
            legacy_findings = []

        # Adapter: promote legacy dicts to unified Finding objects, then serialise
        # back to dicts that include all original keys plus the new unified fields
        # (confidence, cve_refs, target, scan_timestamp, …).  This preserves full
        # backward compatibility while enriching the output with Phase A metadata.
        if _HAS_PLUGINS:
            self.results['vulnerabilities'] = [
                Finding.from_legacy_dict(d, self.target).to_dict()
                for d in legacy_findings
            ]
        else:
            self.results['vulnerabilities'] = legacy_findings

        # [PHASE 2b] Credentialed Scanning (PR1) — runs only when creds are provided
        if _HAS_PLUGINS and credentialed_mode and credential_set is not None:
            print(Colors.header("[PHASE 2b] CREDENTIALED SCANNING"))
            print(Colors.info("Running authenticated connectivity probes...\n"))
            try:
                credential_set.validate_all()
                executor = AuthenticatedExecutor(
                    target=self.target,
                    credential_set=credential_set,
                    timeout=getattr(args, 'timeout', 5.0),
                )
                auth_findings = executor.run_probes()
                ctx = executor.context
                # Store probe metadata (no secrets) in results
                self.results['auth_scan'] = ctx.to_metadata_dict()
                # Append auth probe findings to the unified findings list
                self.results['vulnerabilities'].extend(
                    f.to_dict() for f in auth_findings
                )
                if ctx.authenticated_mode:
                    print(Colors.success(
                        f"  Authenticated scan completed: "
                        f"{sum(1 for r in ctx.probe_results.values() if r.success)} "
                        f"of {len(ctx.probe_results)} probes succeeded\n"
                    ))
                else:
                    print(Colors.warning(
                        "  No authentication probes succeeded — "
                        "check credentials and target availability\n"
                    ))
            except Exception as exc:
                from plugins.secrets import redact_string
                print(Colors.warning(
                    f"  Credentialed scan error: {redact_string(str(exc))}\n"
                ))
                self.results['auth_scan'] = {
                    'authenticated_mode': False,
                    'error': 'Credentialed scan did not complete; see console output.',
                }
        else:
            self.results['auth_scan'] = {'authenticated_mode': False}

        # [PHASE 3] NVD Intelligence (optional)
        if not getattr(args, 'skip_nvd', False):
            nvd = NVDIntelligence(NVD_API_KEY)
            lookback_days = self.results['cve_lookback_days']
            nvd_data = nvd.query_recent_cves(lookback_days)
            self.results['nvd_intelligence'] = {
                'cve_count': len(nvd_data),
                'query_date': datetime.now(timezone.utc).isoformat(),
                'lookback_days': lookback_days,
            }

        # [PHASE 3] Compliance
        if not getattr(args, 'skip_compliance', False):
            compliance_checker = ComplianceChecker(self.results)
            self.results['compliance'] = compliance_checker.check_pci_dss()

        # Finalise scan metadata
        if _HAS_PLUGINS:
            _scan_meta.ended = datetime.now(timezone.utc).isoformat()
            self.results['scan_metadata'] = _scan_meta.to_dict()

        # [PHASE 4] Report Generation
        print(Colors.header("[PHASE 4] REPORT GENERATION"))
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_safe = self.target.replace('.', '_')

        html_file = f"vultron_hybrid_{target_safe}_{timestamp}.html"
        json_file = f"vultron_hybrid_{target_safe}_{timestamp}.json"

        reporter = ReportGenerator(self.results)
        reporter.generate_html(html_file)
        reporter.generate_json(json_file)

        # Summary — counts derived from the single source of truth
        counts = ReportGenerator._count_by_status_severity(self.results['vulnerabilities'])

        print(Colors.header("[SCAN COMPLETE]"))
        print(Colors.success(f"Target: {self.target}"))
        if scan_protocol in ('tcp', 'both'):
            print(Colors.success(
                f"Open TCP Ports: {len(self.results['open_ports'])} (scan mode: {scan_mode})"
            ))
        if scan_protocol in ('udp', 'both'):
            print(Colors.success(
                f"UDP Ports (open/open|filtered): {len(self.results['udp_ports'])}"
            ))
        print(Colors.critical(f"Critical Vulnerabilities (confirmed): {counts['critical_confirmed']}"))
        print(Colors.high(f"High Vulnerabilities (confirmed): {counts['high_confirmed']}"))
        print(Colors.medium(f"Medium Vulnerabilities (confirmed): {counts['medium_confirmed']}"))
        print(Colors.warning(f"Potential (unverified): {counts['potential']}"))
        print(Colors.warning(f"Inconclusive (manual review): {counts['inconclusive']}"))
        print(Colors.warning(f"CISA KEV (confirmed): {counts['kev_confirmed']}"))
        auth_summary = self.results.get('auth_scan', {})
        if credentialed_mode:
            auth_status = "yes" if auth_summary.get('authenticated_mode') else "no"
            print(Colors.info(f"Authenticated Scan: attempted — succeeded: {auth_status}"))
        else:
            print(Colors.info("Authenticated Scan: not attempted (no credentials provided)"))
        print(Colors.success(f"\nReports: {html_file}, {json_file}\n"))


def main():
    parser = argparse.ArgumentParser(
        description='Vultron v4.1 - Defensive Vulnerability Assessment Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python vultron.py -t 192.168.1.100
  python vultron.py -t 192.168.1.100 --scan-mode top1000
  python vultron.py -t 192.168.1.100 --scan-mode full --timeout 2 --concurrency 100
  python vultron.py -t 192.168.1.100 --scan-mode custom --ports 21,80,443,1025-1030,5357
  python vultron.py -t server.local --skip-nvd
  python vultron.py -t 10.0.0.50 --skip-compliance
  python vultron.py -t 192.168.1.100 --cve-lookback-days 30

  # UDP scanning (authorized use only):
  python vultron.py -t 192.168.1.100 --protocol udp
  python vultron.py -t 192.168.1.100 --protocol both --udp-timeout 3 --udp-retries 3
  python vultron.py -t 192.168.1.100 --protocol udp --udp-ports 53,123,161,500

  # Credentialed scanning (authorized use only):
  python vultron.py -t 192.168.1.100 --ssh-user scanuser --ssh-password '<pass>'
  python vultron.py -t 192.168.1.100 --ssh-user scanuser --ssh-key /path/to/id_rsa
  python vultron.py -t 192.168.1.100 --winrm-user Administrator --winrm-password '<pass>'
  python vultron.py -t 192.168.1.100 --wmi-user Administrator --wmi-password '<pass>'
  python vultron.py -t 192.168.1.100 --cred-file /secure/path/creds.json

Scan modes:
  common   Scan 22 well-known ports (fast, default)
  top1000  Scan ~1000 most frequently open ports (includes RPC/high-dyn ports)
  full     Scan all 65535 TCP ports (slow — use with --concurrency 200+)
  custom   Scan ports specified via --ports

Protocol modes:
  tcp   TCP connect scan only (default)
  udp   UDP scan only using protocol-aware probes
  both  Combined TCP + UDP scan

UDP scanning notes:
  UDP scanning requires no elevated privileges.  Probes are lightweight and
  non-intrusive (DNS version query, NTP mode-3 request, SNMP sysDescr read).
  State semantics:
    open          — probe received a response
    open|filtered — no response; port may be open or firewall-filtered
  UDP scanning may produce many open|filtered results on filtered networks.
  Only use on systems and networks you are authorised to test.

Protocol checks (triggered automatically on open TCP ports):
  FTP (21)    Anonymous login probe — CONFIRMED / POTENTIAL / INCONCLUSIVE
  Telnet (23) Banner collection + cleartext exposure — POTENTIAL / INCONCLUSIVE
  SNMP (161)  Default community string probe (public/private) — CONFIRMED / INCONCLUSIVE

Credentialed scanning (all modes):
  SSH probe   TCP reachability + optional authenticated command execution
  WinRM probe TCP reachability + optional authenticated session check
  WMI probe   DCOM reachability + optional authenticated namespace check

  WARNING: Only use credentialed scanning on systems you are authorized to test.
  Credentials are never written to reports or log files.

Capabilities:
  TCP and UDP port discovery, service fingerprinting with version hints and
  confidence scores, and active vulnerability checks.
  CVE enrichment via NVD API, CISA KEV detection, and compliance assessment (PCI DSS).
  Outputs structured HTML and JSON reports with evidence-based, protocol-aware findings.
        """
    )

    parser.add_argument('-t', '--target', required=True,
                        help='Target IP address or hostname')
    parser.add_argument('--scan-mode', choices=['common', 'top1000', 'full', 'custom'],
                        default='common',
                        help='Port scan coverage mode (default: common)')
    parser.add_argument('--ports',
                        help="Custom port list/ranges, e.g. '21,80,443,1025-1030'. "
                             "Required when --scan-mode=custom")
    parser.add_argument('--timeout', type=float, default=1.0, metavar='SECONDS',
                        help='Per-port TCP connection timeout in seconds (default: 1.0)')
    parser.add_argument('--retries', type=int, default=1, metavar='N',
                        help='Retry count per port on failure (default: 1)')
    parser.add_argument('--concurrency', type=int, default=50, metavar='N',
                        help='Maximum concurrent port scan threads (default: 50)')
    parser.add_argument('--skip-nvd', action='store_true',
                        help='Skip NVD CVE enrichment queries')
    parser.add_argument('--skip-compliance', action='store_true',
                        help='Skip compliance assessment')
    parser.add_argument('--cve-lookback-days', type=int, default=120, metavar='DAYS',
                        help='Days to look back for recent CVEs (default: 120, range: 1–3650)')
    parser.add_argument('--version', action='version', version=f'Vultron {VERSION}')

    # -- UDP scanning options (PR2) -----------------------------------------
    udp_group = parser.add_argument_group(
        'UDP scanning (authorized use only)',
        'Options for UDP port discovery.  Only use on systems you are authorised to test.',
    )
    udp_group.add_argument(
        '--protocol',
        choices=['tcp', 'udp', 'both'],
        default='tcp',
        help='Scan protocol selector: tcp (default), udp, or both',
    )
    udp_group.add_argument(
        '--udp-timeout',
        type=float, default=2.0, metavar='SECONDS',
        help='Per-port UDP probe receive timeout in seconds (default: 2.0)',
    )
    udp_group.add_argument(
        '--udp-retries',
        type=int, default=2, metavar='N',
        help='Total UDP probe attempts per port (default: 2)',
    )
    udp_group.add_argument(
        '--udp-ports',
        metavar='PORTS',
        help="Custom UDP port list/ranges, e.g. '53,123,161,500-514'. "
             "Defaults to common UDP service ports when not specified.",
    )

    # -- Credentialed scanning options (PR1) --------------------------------
    cred_group = parser.add_argument_group(
        'Credentialed scanning (authorized use only)',
        'Provide credentials to enable authenticated probes. '
        'Credentials are never written to reports or log output.',
    )
    cred_group.add_argument('--cred-file', metavar='FILE',
                            help='Path to a JSON credential file. '
                                 'See documentation for the expected format.')
    # SSH
    cred_group.add_argument('--ssh-user', metavar='USERNAME',
                            help='SSH username for credentialed SSH probe')
    cred_group.add_argument('--ssh-password', metavar='PASSWORD',
                            help='SSH password (use --ssh-key for key-based auth)')
    cred_group.add_argument('--ssh-key', metavar='PATH',
                            help='Path to SSH private key file')
    cred_group.add_argument('--ssh-port', type=int, default=22, metavar='PORT',
                            help='SSH port (default: 22)')
    # WinRM
    cred_group.add_argument('--winrm-user', metavar='USERNAME',
                            help='WinRM username for credentialed WinRM probe')
    cred_group.add_argument('--winrm-password', metavar='PASSWORD',
                            help='WinRM password')
    cred_group.add_argument('--winrm-domain', metavar='DOMAIN',
                            help='Active Directory domain for WinRM authentication')
    cred_group.add_argument('--winrm-transport',
                            choices=['http', 'https'], default='http',
                            help='WinRM transport (default: http)')
    # WMI
    cred_group.add_argument('--wmi-user', metavar='USERNAME',
                            help='WMI username for credentialed WMI probe')
    cred_group.add_argument('--wmi-password', metavar='PASSWORD',
                            help='WMI password')
    cred_group.add_argument('--wmi-domain', metavar='DOMAIN',
                            help='Active Directory domain for WMI authentication')

    args = parser.parse_args()

    if args.scan_mode == 'custom' and not args.ports:
        parser.error("--ports is required when --scan-mode=custom")
    if args.cve_lookback_days < 1:
        parser.error("--cve-lookback-days must be a positive integer (got "
                     f"{args.cve_lookback_days})")
    if args.cve_lookback_days > 3650:
        parser.error("--cve-lookback-days must be 3650 or less (got "
                     f"{args.cve_lookback_days})")
    if getattr(args, 'ssh_password', None) and getattr(args, 'ssh_key', None):
        parser.error("--ssh-password and --ssh-key are mutually exclusive")

    scanner = HybridScanner(args.target, args)
    scanner.run()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(Colors.warning("\n\n[!] Scan interrupted by user"))
        sys.exit(1)
    except Exception as e:
        print(Colors.critical(f"\n[ERROR] {e}"))
        import traceback
        traceback.print_exc()
        sys.exit(1)
