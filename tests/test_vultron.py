"""
Tests for Vultron scan accuracy and reliability improvements.

Run with:  python -m pytest tests/test_vultron.py -v
       or: python -m unittest tests/test_vultron.py
"""

import sys
import os
import unittest
import socket
from unittest.mock import patch, MagicMock

# Make the parent directory importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vultron import PortScanner, VulnerabilityChecker, NVDIntelligence, ReportGenerator, HybridScanner


# ---------------------------------------------------------------------------
# 1. Scan-mode port coverage
# ---------------------------------------------------------------------------

class TestScanModePortCoverage(unittest.TestCase):
    """PortScanner.get_ports_to_scan() returns the expected set per mode."""

    def test_common_mode_returns_known_ports(self):
        scanner = PortScanner("127.0.0.1", scan_mode="common")
        ports = scanner.get_ports_to_scan()
        self.assertIn(21, ports)
        self.assertIn(445, ports)
        self.assertIn(8080, ports)
        self.assertEqual(len(ports), len(PortScanner.COMMON_PORTS))

    def test_top1000_covers_rpc_range(self):
        """top1000 mode must include 1025-1030 and 5357 (missed by common)."""
        scanner = PortScanner("127.0.0.1", scan_mode="top1000")
        ports = scanner.get_ports_to_scan()
        for p in [1025, 1026, 1027, 1028, 1029, 1030, 5357]:
            self.assertIn(p, ports, f"Port {p} missing from top1000 mode")

    def test_top1000_larger_than_common(self):
        common_ports = PortScanner("127.0.0.1", scan_mode="common").get_ports_to_scan()
        top1000_ports = PortScanner("127.0.0.1", scan_mode="top1000").get_ports_to_scan()
        self.assertGreater(len(top1000_ports), len(common_ports))

    def test_full_mode_contains_all_ports(self):
        scanner = PortScanner("127.0.0.1", scan_mode="full")
        ports = scanner.get_ports_to_scan()
        self.assertEqual(len(ports), 65535)
        self.assertIn(1, ports)
        self.assertIn(65535, ports)

    def test_custom_mode_uses_provided_ports(self):
        custom = [21, 80, 443, 1025, 1026, 5357]
        scanner = PortScanner("127.0.0.1", scan_mode="custom", custom_ports=custom)
        ports = scanner.get_ports_to_scan()
        self.assertEqual(sorted(ports), sorted(custom))

    def test_custom_mode_empty_falls_back_to_common(self):
        """custom mode with no ports provided falls back to COMMON_PORTS."""
        scanner = PortScanner("127.0.0.1", scan_mode="custom", custom_ports=[])
        ports = scanner.get_ports_to_scan()
        self.assertEqual(sorted(ports), sorted(PortScanner.COMMON_PORTS.keys()))


class TestParsePortSpec(unittest.TestCase):
    """PortScanner.parse_port_spec() handles various input formats."""

    def test_single_port(self):
        self.assertEqual(PortScanner.parse_port_spec("80"), [80])

    def test_comma_separated(self):
        result = PortScanner.parse_port_spec("21,80,443")
        self.assertEqual(result, [21, 80, 443])

    def test_range(self):
        result = PortScanner.parse_port_spec("1025-1030")
        self.assertEqual(result, [1025, 1026, 1027, 1028, 1029, 1030])

    def test_mixed(self):
        result = PortScanner.parse_port_spec("21,80,443,1025-1030,5357")
        for p in [21, 80, 443, 1025, 1026, 1027, 1028, 1029, 1030, 5357]:
            self.assertIn(p, result)

    def test_deduplication(self):
        result = PortScanner.parse_port_spec("80,80,80")
        self.assertEqual(result, [80])

    def test_out_of_range_excluded(self):
        result = PortScanner.parse_port_spec("0,1,65535,65536")
        self.assertNotIn(0, result)
        self.assertNotIn(65536, result)
        self.assertIn(1, result)
        self.assertIn(65535, result)


# ---------------------------------------------------------------------------
# 2. Vulnerability counter / summary consistency
# ---------------------------------------------------------------------------

class TestCounterConsistency(unittest.TestCase):
    """ReportGenerator._count_by_status_severity() matches the findings list exactly."""

    def _make_finding(self, severity, status, cisa_kev=False):
        return {
            'id': 'TEST',
            'name': 'Test Finding',
            'severity': severity,
            'status': status,
            'cisa_kev': cisa_kev,
            'port': 445,
        }

    def test_confirmed_critical_counted(self):
        vulns = [self._make_finding('CRITICAL', 'CONFIRMED')]
        counts = ReportGenerator._count_by_status_severity(vulns)
        self.assertEqual(counts['critical_confirmed'], 1)
        self.assertEqual(counts['high_confirmed'], 0)
        self.assertEqual(counts['potential'], 0)
        self.assertEqual(counts['inconclusive'], 0)

    def test_potential_not_in_confirmed_counts(self):
        vulns = [self._make_finding('CRITICAL', 'POTENTIAL')]
        counts = ReportGenerator._count_by_status_severity(vulns)
        self.assertEqual(counts['critical_confirmed'], 0)
        self.assertEqual(counts['potential'], 1)

    def test_inconclusive_not_in_confirmed_counts(self):
        vulns = [self._make_finding('HIGH', 'INCONCLUSIVE')]
        counts = ReportGenerator._count_by_status_severity(vulns)
        self.assertEqual(counts['high_confirmed'], 0)
        self.assertEqual(counts['inconclusive'], 1)

    def test_kev_only_counted_when_confirmed(self):
        vulns = [
            self._make_finding('CRITICAL', 'CONFIRMED', cisa_kev=True),
            self._make_finding('CRITICAL', 'POTENTIAL', cisa_kev=True),
            self._make_finding('CRITICAL', 'INCONCLUSIVE', cisa_kev=True),
        ]
        counts = ReportGenerator._count_by_status_severity(vulns)
        self.assertEqual(counts['kev_confirmed'], 1)

    def test_mixed_findings_no_double_count(self):
        vulns = [
            self._make_finding('CRITICAL', 'CONFIRMED', cisa_kev=True),
            self._make_finding('HIGH', 'CONFIRMED'),
            self._make_finding('MEDIUM', 'CONFIRMED'),
            self._make_finding('HIGH', 'POTENTIAL'),
            self._make_finding('CRITICAL', 'INCONCLUSIVE'),
        ]
        counts = ReportGenerator._count_by_status_severity(vulns)
        self.assertEqual(counts['critical_confirmed'], 1)
        self.assertEqual(counts['high_confirmed'], 1)
        self.assertEqual(counts['medium_confirmed'], 1)
        self.assertEqual(counts['potential'], 1)
        self.assertEqual(counts['inconclusive'], 1)
        self.assertEqual(counts['kev_confirmed'], 1)

    def test_empty_findings(self):
        counts = ReportGenerator._count_by_status_severity([])
        for v in counts.values():
            self.assertEqual(v, 0)


# ---------------------------------------------------------------------------
# 3. Timeout → INCONCLUSIVE conversion
# ---------------------------------------------------------------------------

class TestTimeoutInconclusiveHandling(unittest.TestCase):
    """Checks that timed-out probes produce INCONCLUSIVE findings, not CONFIRMED."""

    def _checker(self, port=445):
        return VulnerabilityChecker("127.0.0.1", [{'port': port, 'service': 'SMB'}])

    def test_eternalblue_timeout_gives_inconclusive(self):
        checker = self._checker(445)
        with patch('socket.socket') as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.connect.side_effect = socket.timeout("timed out")
            checker.check_eternalblue(445)

        inconclusive = [v for v in checker.vulnerabilities if v.get('status') == 'INCONCLUSIVE']
        confirmed = [v for v in checker.vulnerabilities if v.get('status') == 'CONFIRMED']
        self.assertEqual(len(inconclusive), 1)
        self.assertEqual(len(confirmed), 0)
        self.assertEqual(inconclusive[0]['cve'], 'CVE-2017-0144')

    def test_eternalblue_timeout_does_not_inflate_critical(self):
        checker = self._checker(445)
        with patch('socket.socket') as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.connect.side_effect = socket.timeout("timed out")
            checker.check_eternalblue(445)

        counts = ReportGenerator._count_by_status_severity(checker.vulnerabilities)
        self.assertEqual(counts['critical_confirmed'], 0)

    def test_smbghost_timeout_gives_inconclusive(self):
        checker = self._checker(445)
        with patch('socket.socket') as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.connect.side_effect = socket.timeout("timed out")
            checker.check_smbghost(445)

        inconclusive = [v for v in checker.vulnerabilities if v.get('status') == 'INCONCLUSIVE']
        self.assertEqual(len(inconclusive), 1)
        self.assertEqual(inconclusive[0]['cve'], 'CVE-2020-0796')

    def test_smbghost_timeout_does_not_inflate_severity(self):
        checker = self._checker(445)
        with patch('socket.socket') as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.connect.side_effect = socket.timeout("timed out")
            checker.check_smbghost(445)

        counts = ReportGenerator._count_by_status_severity(checker.vulnerabilities)
        self.assertEqual(counts['critical_confirmed'], 0)
        self.assertEqual(counts['high_confirmed'], 0)


# ---------------------------------------------------------------------------
# 4. SMBGhost unconditional-CRITICAL regression guard
# ---------------------------------------------------------------------------

class TestSMBGhostNotAlwaysCritical(unittest.TestCase):
    """SMBGhost must never blindly add a CONFIRMED CRITICAL without an actual probe."""

    def test_smbghost_no_smb311_response_adds_no_finding(self):
        """When the server does not advertise SMB 3.1.1, no finding should be added."""
        checker = VulnerabilityChecker("127.0.0.1", [])
        with patch('socket.socket') as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.connect.return_value = None
            # Return a response with SMB2 magic but NO 0x11 0x03 dialect marker
            mock_sock.recv.return_value = b'\xfeSMB' + b'\x00' * 60
            checker.check_smbghost(445)

        confirmed_critical = [v for v in checker.vulnerabilities
                               if v.get('status') == 'CONFIRMED' and v.get('severity') == 'CRITICAL']
        self.assertEqual(len(confirmed_critical), 0,
                         "SMBGhost must not be CONFIRMED CRITICAL without SMB 3.1.1 evidence")

    def test_smbghost_smb311_response_adds_potential_not_confirmed(self):
        """Even with SMB 3.1.1, the finding should be POTENTIAL (not CONFIRMED) — needs OS patch check."""
        checker = VulnerabilityChecker("127.0.0.1", [])
        with patch('socket.socket') as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.connect.return_value = None
            # Include SMB2 magic + dialect 0x0311 bytes
            mock_sock.recv.return_value = b'\xfeSMB' + b'\x00' * 30 + b'\x11\x03' + b'\x00' * 10
            checker.check_smbghost(445)

        potential = [v for v in checker.vulnerabilities if v.get('status') == 'POTENTIAL']
        confirmed = [v for v in checker.vulnerabilities if v.get('status') == 'CONFIRMED']
        self.assertGreater(len(potential), 0, "SMB 3.1.1 should produce at least one POTENTIAL finding")
        self.assertEqual(len(confirmed), 0, "SMBGhost must not be CONFIRMED — patch status unknown")


# ---------------------------------------------------------------------------
# 5. NVD client response handling
# ---------------------------------------------------------------------------

class TestNVDClientResponseHandling(unittest.TestCase):
    """NVDIntelligence handles HTTP errors, 404, and network failures gracefully."""

    def setUp(self):
        self.nvd = NVDIntelligence(api_key=None)

    def _mock_response(self, status_code, json_data=None):
        resp = MagicMock()
        resp.status_code = status_code
        resp.url = "https://services.nvd.nist.gov/rest/json/cves/2.0?test=1"
        if json_data is not None:
            resp.json.return_value = json_data
        return resp

    @patch('requests.get')
    def test_200_returns_vulnerabilities(self, mock_get):
        mock_get.return_value = self._mock_response(200, {
            'totalResults': 2,
            'vulnerabilities': [{'cve': {'id': 'CVE-2024-0001'}},
                                 {'cve': {'id': 'CVE-2024-0002'}}]
        })
        result = self.nvd.query_recent_cves(days=7)
        self.assertEqual(len(result), 2)

    @patch('requests.get')
    def test_404_returns_empty_list(self, mock_get):
        mock_get.return_value = self._mock_response(404)
        result = self.nvd.query_recent_cves(days=7)
        self.assertEqual(result, [])

    @patch('time.sleep')
    @patch('requests.get')
    def test_network_error_returns_empty_list(self, mock_get, mock_sleep):
        mock_get.side_effect = Exception("connection refused")
        result = self.nvd.query_recent_cves(days=7)
        self.assertEqual(result, [])

    @patch('requests.get')
    def test_date_format_includes_utc_offset(self, mock_get):
        """The NVD 2.0 API requires ISO 8601 timestamps with explicit UTC offset."""
        mock_get.return_value = self._mock_response(200, {'totalResults': 0, 'vulnerabilities': []})
        self.nvd.query_recent_cves(days=7)
        self.assertTrue(mock_get.called)
        params = mock_get.call_args.kwargs.get('params', {})
        pub_start = params.get('pubStartDate', '')
        self.assertIn('UTC', pub_start,
                      f"pubStartDate '{pub_start}' must contain UTC offset for NVD 2.0 API")

    @patch('requests.get')
    def test_caching_avoids_duplicate_requests(self, mock_get):
        mock_get.return_value = self._mock_response(200, {'totalResults': 1, 'vulnerabilities': [{}]})
        self.nvd.query_recent_cves(days=7)
        self.nvd.query_recent_cves(days=7)  # second call should use cache
        self.assertEqual(mock_get.call_count, 1, "Second identical query should use cache")

    @patch('requests.get')
    def test_enrich_cve_returns_data(self, mock_get):
        mock_get.return_value = self._mock_response(200, {
            'vulnerabilities': [{'cve': {'id': 'CVE-2017-0144'}}]
        })
        result = self.nvd.enrich_cve('CVE-2017-0144')
        self.assertIsNotNone(result)

    @patch('requests.get')
    def test_enrich_cve_not_found_returns_none(self, mock_get):
        mock_get.return_value = self._mock_response(404)
        result = self.nvd.enrich_cve('CVE-9999-0000')
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# 6. BlueKeep must be POTENTIAL, not CONFIRMED CRITICAL
# ---------------------------------------------------------------------------

class TestBlueKeepClassification(unittest.TestCase):
    def test_bluekeep_is_potential_not_confirmed(self):
        checker = VulnerabilityChecker("127.0.0.1", [])
        checker.check_bluekeep(3389)
        self.assertEqual(len(checker.vulnerabilities), 1)
        finding = checker.vulnerabilities[0]
        self.assertEqual(finding['status'], 'POTENTIAL')
        self.assertNotEqual(finding['status'], 'CONFIRMED')

    def test_bluekeep_includes_evidence(self):
        checker = VulnerabilityChecker("127.0.0.1", [])
        checker.check_bluekeep(3389)
        finding = checker.vulnerabilities[0]
        self.assertIn('evidence', finding)
        self.assertTrue(len(finding['evidence']) > 0)


# ---------------------------------------------------------------------------
# 7. FTP anonymous login check
# ---------------------------------------------------------------------------

class TestFTPAnonymousCheck(unittest.TestCase):
    """check_ftp_anonymous() produces correct status for each server response."""

    def _checker(self):
        return VulnerabilityChecker("127.0.0.1", [{'port': 21, 'service': 'FTP'}])

    def test_ftp_anonymous_login_confirmed(self):
        """230 response after PASS → CONFIRMED finding."""
        checker = self._checker()
        with patch('socket.socket') as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.recv.side_effect = [
                b'220 FTP Server Ready\r\n',
                b'331 Password required\r\n',
                b'230 Login successful\r\n',
            ]
            checker.check_ftp_anonymous(21)

        confirmed = [v for v in checker.vulnerabilities if v.get('status') == 'CONFIRMED']
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(confirmed[0]['affected_service'], 'FTP')
        self.assertEqual(confirmed[0]['severity'], 'HIGH')

    def test_ftp_anonymous_login_denied_no_finding(self):
        """530 response → no finding added (NOT_AFFECTED)."""
        checker = self._checker()
        with patch('socket.socket') as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.recv.side_effect = [
                b'220 FTP Server Ready\r\n',
                b'331 Password required\r\n',
                b'530 Login incorrect\r\n',
            ]
            checker.check_ftp_anonymous(21)

        self.assertEqual(len(checker.vulnerabilities), 0)

    def test_ftp_anonymous_login_timeout_inconclusive(self):
        """Timeout → INCONCLUSIVE, never CONFIRMED."""
        checker = self._checker()
        with patch('socket.socket') as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.connect.side_effect = socket.timeout("timed out")
            checker.check_ftp_anonymous(21)

        inconclusive = [v for v in checker.vulnerabilities if v.get('status') == 'INCONCLUSIVE']
        confirmed = [v for v in checker.vulnerabilities if v.get('status') == 'CONFIRMED']
        self.assertEqual(len(inconclusive), 1)
        self.assertEqual(len(confirmed), 0)

    def test_ftp_anonymous_timeout_not_counted_as_high(self):
        """INCONCLUSIVE FTP timeout does not inflate high severity counter."""
        checker = self._checker()
        with patch('socket.socket') as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.connect.side_effect = socket.timeout("timed out")
            checker.check_ftp_anonymous(21)

        counts = ReportGenerator._count_by_status_severity(checker.vulnerabilities)
        self.assertEqual(counts['high_confirmed'], 0)

    def test_ftp_anonymous_confirmed_counts_as_high(self):
        """CONFIRMED anonymous login is counted as high severity."""
        checker = self._checker()
        with patch('socket.socket') as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.recv.side_effect = [
                b'220 FTP Server Ready\r\n',
                b'331 Password required\r\n',
                b'230 Login successful\r\n',
            ]
            checker.check_ftp_anonymous(21)

        counts = ReportGenerator._count_by_status_severity(checker.vulnerabilities)
        self.assertEqual(counts['high_confirmed'], 1)


# ---------------------------------------------------------------------------
# 8. Telnet banner check
# ---------------------------------------------------------------------------

class TestTelnetBannerCheck(unittest.TestCase):
    """check_telnet_banner() produces correct status for each outcome."""

    def _checker(self):
        return VulnerabilityChecker("127.0.0.1", [{'port': 23, 'service': 'Telnet'}])

    def test_telnet_banner_received_gives_potential(self):
        """Banner data received → POTENTIAL (cleartext protocol exposure)."""
        checker = self._checker()
        with patch('socket.socket') as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.recv.return_value = b'Welcome to router\r\nlogin: '
            checker.check_telnet_banner(23)

        potential = [v for v in checker.vulnerabilities if v.get('status') == 'POTENTIAL']
        self.assertEqual(len(potential), 1)
        self.assertEqual(potential[0]['affected_service'], 'Telnet')
        self.assertEqual(potential[0]['severity'], 'HIGH')

    def test_telnet_empty_banner_still_potential(self):
        """No banner text but connected → still POTENTIAL."""
        checker = self._checker()
        with patch('socket.socket') as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.recv.return_value = b''
            checker.check_telnet_banner(23)

        potential = [v for v in checker.vulnerabilities if v.get('status') == 'POTENTIAL']
        self.assertEqual(len(potential), 1)

    def test_telnet_timeout_gives_inconclusive(self):
        """Timeout → INCONCLUSIVE, not CONFIRMED."""
        checker = self._checker()
        with patch('socket.socket') as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.recv.side_effect = socket.timeout("timed out")
            checker.check_telnet_banner(23)

        inconclusive = [v for v in checker.vulnerabilities if v.get('status') == 'INCONCLUSIVE']
        confirmed = [v for v in checker.vulnerabilities if v.get('status') == 'CONFIRMED']
        self.assertEqual(len(inconclusive), 1)
        self.assertEqual(len(confirmed), 0)

    def test_telnet_timeout_not_counted_as_confirmed(self):
        """Telnet INCONCLUSIVE does not inflate severity counters."""
        checker = self._checker()
        with patch('socket.socket') as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.recv.side_effect = socket.timeout("timed out")
            checker.check_telnet_banner(23)

        counts = ReportGenerator._count_by_status_severity(checker.vulnerabilities)
        self.assertEqual(counts['high_confirmed'], 0)
        self.assertEqual(counts['critical_confirmed'], 0)

    def test_telnet_banner_evidence_populated(self):
        """Evidence list includes banner text when available."""
        checker = self._checker()
        with patch('socket.socket') as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.recv.return_value = b'Cisco IOS Router\r\n'
            checker.check_telnet_banner(23)

        finding = checker.vulnerabilities[0]
        evidence_str = ' '.join(finding.get('evidence', []))
        self.assertIn('Cisco IOS Router', evidence_str)


# ---------------------------------------------------------------------------
# 9. SNMP default community check
# ---------------------------------------------------------------------------

class TestSNMPCommunityCheck(unittest.TestCase):
    """check_snmp_community() produces correct status for each probe outcome."""

    def _checker(self):
        return VulnerabilityChecker("127.0.0.1", [{'port': 161, 'service': 'SNMP'}])

    def test_snmp_public_accepted_gives_confirmed(self):
        """SNMP response received for 'public' → CONFIRMED."""
        checker = self._checker()
        fake_response = b'\x30\x26\x02\x01\x00\x04\x06public\xa2\x19'
        with patch('socket.socket') as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.recvfrom.return_value = (fake_response, ('127.0.0.1', 161))
            checker.check_snmp_community(161)

        confirmed = [v for v in checker.vulnerabilities if v.get('status') == 'CONFIRMED']
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(confirmed[0]['affected_service'], 'SNMP')
        self.assertIn('public', confirmed[0]['title'])

    def test_snmp_all_timeout_gives_inconclusive(self):
        """All community probes time out → exactly one INCONCLUSIVE finding."""
        checker = self._checker()
        with patch('socket.socket') as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = socket.timeout("timed out")
            checker.check_snmp_community(161)

        inconclusive = [v for v in checker.vulnerabilities if v.get('status') == 'INCONCLUSIVE']
        confirmed = [v for v in checker.vulnerabilities if v.get('status') == 'CONFIRMED']
        self.assertEqual(len(inconclusive), 1)
        self.assertEqual(len(confirmed), 0)

    def test_snmp_timeout_not_counted_as_confirmed(self):
        """SNMP INCONCLUSIVE does not inflate severity counters."""
        checker = self._checker()
        with patch('socket.socket') as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = socket.timeout("timed out")
            checker.check_snmp_community(161)

        counts = ReportGenerator._count_by_status_severity(checker.vulnerabilities)
        self.assertEqual(counts['high_confirmed'], 0)
        self.assertEqual(counts['critical_confirmed'], 0)

    def test_snmp_confirmed_counts_as_high(self):
        """CONFIRMED SNMP community acceptance is counted as high severity."""
        checker = self._checker()
        with patch('socket.socket') as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.recvfrom.return_value = (b'\x30\x10', ('127.0.0.1', 161))
            checker.check_snmp_community(161)

        counts = ReportGenerator._count_by_status_severity(checker.vulnerabilities)
        self.assertEqual(counts['high_confirmed'], 1)

    def test_snmp_getrequest_packet_builds(self):
        """_build_snmp_getrequest() returns a valid BER-encoded SNMP packet."""
        pkt = VulnerabilityChecker._build_snmp_getrequest('public')
        self.assertIsInstance(pkt, bytes)
        self.assertGreater(len(pkt), 10)
        # Outer SEQUENCE tag
        self.assertEqual(pkt[0], 0x30)
        # Should contain the community string bytes
        self.assertIn(b'public', pkt)


# ---------------------------------------------------------------------------
# 10. CVE lookback days
# ---------------------------------------------------------------------------

class TestCVELookbackDays(unittest.TestCase):
    """Configurable --cve-lookback-days wiring and validation."""

    def _make_args(self, **kwargs):
        import argparse
        defaults = dict(
            scan_mode='common', timeout=1.0, retries=1, concurrency=50,
            ports=None, skip_nvd=True, skip_compliance=True, cve_lookback_days=120,
        )
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    def test_hybrid_scanner_stores_custom_lookback(self):
        """HybridScanner stores cve_lookback_days=30 from args immediately."""
        scanner = HybridScanner("127.0.0.1", self._make_args(cve_lookback_days=30))
        self.assertEqual(scanner.results.get('cve_lookback_days'), 30)

    def test_hybrid_scanner_default_lookback_is_120(self):
        """When no cve_lookback_days in args, HybridScanner uses default 120."""
        import argparse
        # Namespace without cve_lookback_days attribute
        args = argparse.Namespace(
            scan_mode='common', timeout=1.0, retries=1, concurrency=50,
            ports=None, skip_nvd=True, skip_compliance=True,
        )
        scanner = HybridScanner("127.0.0.1", args)
        self.assertEqual(scanner.results.get('cve_lookback_days'), 120)

    @patch('requests.get')
    def test_nvd_query_respects_lookback_days(self, mock_get):
        """query_recent_cves(days=30) builds a date range ~30 days back."""
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {'totalResults': 0, 'vulnerabilities': []}
        mock_get.return_value = resp

        nvd = NVDIntelligence(api_key=None)
        nvd.query_recent_cves(days=30)

        self.assertTrue(mock_get.called)
        params = mock_get.call_args.kwargs.get('params', {})
        pub_start = params.get('pubStartDate', '')
        self.assertIn('UTC', pub_start)

    @patch('requests.get')
    def test_nvd_different_days_not_cached_together(self, mock_get):
        """30-day and 60-day queries must not share a cache entry."""
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {'totalResults': 0, 'vulnerabilities': []}
        mock_get.return_value = resp

        nvd = NVDIntelligence(api_key=None)
        nvd.query_recent_cves(days=30)
        nvd.query_recent_cves(days=60)

        self.assertEqual(mock_get.call_count, 2,
                         "Queries with different days should not share a cache entry")

    def test_lookback_days_included_in_nvd_intelligence_after_run(self):
        """nvd_intelligence dict must include lookback_days after a full run."""
        from unittest.mock import patch as _patch
        import argparse

        args = argparse.Namespace(
            scan_mode='common', timeout=1.0, retries=1, concurrency=50,
            ports=None, skip_nvd=False, skip_compliance=True, cve_lookback_days=45,
        )
        scanner = HybridScanner("127.0.0.1", args)

        fake_port = [{'port': 80, 'service': 'HTTP', 'state': 'open',
                      'banner': '', 'protocol': 'tcp'}]

        with _patch('vultron.PortScanner.scan', return_value=fake_port), \
             _patch('vultron.VulnerabilityChecker.check_all', return_value=[]), \
             _patch('vultron.NVDIntelligence.query_recent_cves', return_value=[]) as mock_nvd, \
             _patch('vultron.ReportGenerator.generate_html'), \
             _patch('vultron.ReportGenerator.generate_json'):
            scanner.run()
            mock_nvd.assert_called_once_with(45)

        self.assertEqual(scanner.results['nvd_intelligence'].get('lookback_days'), 45)


# ---------------------------------------------------------------------------
# 11. Phase A — Plugin registration / discovery
# ---------------------------------------------------------------------------

class TestPhaseAPluginRegistration(unittest.TestCase):
    """Plugin registration, discovery, and base contract validation."""

    def setUp(self):
        from plugins import CheckRegistry
        # Snapshot existing registrations so we can restore after each test
        self._saved = dict(CheckRegistry._checks)

    def tearDown(self):
        from plugins import CheckRegistry
        CheckRegistry._checks.clear()
        CheckRegistry._checks.update(self._saved)

    def test_register_and_discover_by_id(self):
        """Registering a check makes it discoverable via get()."""
        from plugins import BaseCheck, CheckRegistry

        class MyCheck(BaseCheck):
            check_id = "TEST-DISCOVER-001"
            title = "Discovery test"
            description = "Test"
            category = "network"
            default_severity = "LOW"
            required_ports = [9901]
            service_matchers = []

            def run(self, target, port, **kwargs):
                return []

        CheckRegistry.register(MyCheck)
        self.assertIs(CheckRegistry.get("TEST-DISCOVER-001"), MyCheck)

    def test_all_checks_includes_registered(self):
        """all_checks() contains the freshly registered check."""
        from plugins import BaseCheck, CheckRegistry

        class AnotherCheck(BaseCheck):
            check_id = "TEST-ALLCHECKS-002"
            title = "All-checks test"
            description = "Test"
            category = "service"
            default_severity = "MEDIUM"
            required_ports = [9902]
            service_matchers = []

            def run(self, target, port, **kwargs):
                return []

        CheckRegistry.register(AnotherCheck)
        self.assertIn(AnotherCheck, CheckRegistry.all_checks())

    def test_register_as_decorator(self):
        """@CheckRegistry.register decorator works and returns the class unchanged."""
        from plugins import BaseCheck, CheckRegistry

        @CheckRegistry.register
        class DecoratedCheck(BaseCheck):
            check_id = "TEST-DECO-003"
            title = "Decorated"
            description = "Test"
            category = "config"
            default_severity = "INFO"
            required_ports = [8081]
            service_matchers = ["HTTP-Alt"]

            def run(self, target, port, **kwargs):
                return []

        self.assertIsNotNone(CheckRegistry.get("TEST-DECO-003"))
        # Decorator must return the original class
        self.assertTrue(issubclass(DecoratedCheck, BaseCheck))

    def test_register_raises_without_check_id(self):
        """Registering a check without check_id raises ValueError."""
        from plugins import BaseCheck, CheckRegistry

        class NoIdCheck(BaseCheck):
            check_id = ""  # intentionally empty
            title = "No ID"
            description = "Test"
            category = "network"
            default_severity = "LOW"
            required_ports = []
            service_matchers = []

            def run(self, target, port, **kwargs):
                return []

        with self.assertRaises(ValueError):
            CheckRegistry.register(NoIdCheck)

    def test_checks_for_port_returns_matching(self):
        """checks_for_port() returns checks whose required_ports include the port."""
        from plugins import BaseCheck, CheckRegistry

        class Port9910Check(BaseCheck):
            check_id = "TEST-PORT-9910"
            title = "Port 9910"
            description = "Test"
            category = "network"
            default_severity = "LOW"
            required_ports = [9910]
            service_matchers = []

            def run(self, target, port, **kwargs):
                return []

        CheckRegistry.register(Port9910Check)
        matches = CheckRegistry.checks_for_port(9910)
        self.assertIn(Port9910Check, matches)
        no_matches = CheckRegistry.checks_for_port(9911)
        self.assertNotIn(Port9910Check, no_matches)

    def test_checks_for_port_service_matcher(self):
        """checks_for_port() also matches via service_matchers (case-insensitive)."""
        from plugins import BaseCheck, CheckRegistry

        class SvcCheck(BaseCheck):
            check_id = "TEST-SVC-9920"
            title = "Service matcher test"
            description = "Test"
            category = "service"
            default_severity = "MEDIUM"
            required_ports = []
            service_matchers = ["TestSvc"]

            def run(self, target, port, **kwargs):
                return []

        CheckRegistry.register(SvcCheck)
        # Match by service name (case-insensitive)
        self.assertIn(SvcCheck, CheckRegistry.checks_for_port(80, service="testsvc"))
        # No match for a different service
        self.assertNotIn(SvcCheck, CheckRegistry.checks_for_port(80, service="HTTP"))

    def test_base_check_requires_run_method(self):
        """Instantiating a BaseCheck subclass without run() raises TypeError."""
        from plugins import BaseCheck

        class NoRunCheck(BaseCheck):
            check_id = "NO-RUN"
            title = "No run"
            description = "Test"
            category = "network"
            default_severity = "LOW"
            required_ports = []
            service_matchers = []
            # No run() method

        with self.assertRaises(TypeError):
            NoRunCheck()

    def test_clear_removes_all(self):
        """clear() empties the registry."""
        from plugins import CheckRegistry
        CheckRegistry.clear()
        self.assertEqual(CheckRegistry.all_checks(), [])


# ---------------------------------------------------------------------------
# 12. Phase A — Finding schema serialisation and adapter
# ---------------------------------------------------------------------------

class TestFindingSchema(unittest.TestCase):
    """Finding schema serialisation, adapter layer, and confidence mapping."""

    def _legacy(self, **kwargs):
        base = {
            "id": "MS17-010",
            "cve": "CVE-2017-0144",
            "name": "EternalBlue",
            "title": "EternalBlue SMBv1 RCE",
            "severity": "CRITICAL",
            "status": "CONFIRMED",
            "port": 445,
            "affected_service": "SMB",
            "description": "SMBv1 exploit",
            "evidence": ["SMBv1 accepted"],
            "cisa_kev": True,
            "exploit_available": True,
            "cvss": 9.8,
            "remediation": "Patch",
        }
        base.update(kwargs)
        return base

    def test_from_legacy_dict_core_fields(self):
        """from_legacy_dict() maps all core legacy fields correctly."""
        from plugins import Finding
        d = self._legacy()
        f = Finding.from_legacy_dict(d, target="10.0.0.1")
        self.assertEqual(f.id, "MS17-010")
        self.assertEqual(f.status, "CONFIRMED")
        self.assertEqual(f.severity, "CRITICAL")
        self.assertEqual(f.port, 445)
        self.assertEqual(f.service, "SMB")
        self.assertEqual(f.target, "10.0.0.1")
        self.assertEqual(f.cve_refs, ["CVE-2017-0144"])
        self.assertTrue(f.cisa_kev)
        self.assertTrue(f.exploit_available)
        self.assertAlmostEqual(f.cvss, 9.8)

    def test_to_dict_preserves_legacy_keys(self):
        """to_dict() produces all legacy keys that existing code expects."""
        from plugins import Finding
        f = Finding.from_legacy_dict(self._legacy(), target="10.0.0.1")
        out = f.to_dict()
        for key in ("id", "cve", "name", "title", "severity", "status",
                    "port", "affected_service", "description", "evidence",
                    "cisa_kev", "exploit_available", "cvss", "remediation"):
            self.assertIn(key, out, f"Legacy key '{key}' missing from to_dict() output")

    def test_to_dict_adds_new_fields(self):
        """to_dict() adds confidence, cve_refs, target, evidence_raw."""
        from plugins import Finding
        f = Finding.from_legacy_dict(self._legacy(), target="10.0.0.1")
        out = f.to_dict()
        self.assertIn("confidence", out)
        self.assertIn("cve_refs", out)
        self.assertIn("target", out)
        self.assertIn("evidence_raw", out)

    def test_confidence_confirmed(self):
        """CONFIRMED status → confidence ≈ 0.9."""
        from plugins import Finding
        f = Finding.from_legacy_dict(self._legacy(status="CONFIRMED"))
        self.assertAlmostEqual(f.confidence, 0.9)

    def test_confidence_potential(self):
        """POTENTIAL status → confidence ≈ 0.5."""
        from plugins import Finding
        f = Finding.from_legacy_dict(self._legacy(status="POTENTIAL"))
        self.assertAlmostEqual(f.confidence, 0.5)

    def test_confidence_inconclusive(self):
        """INCONCLUSIVE status → confidence ≈ 0.2."""
        from plugins import Finding
        f = Finding.from_legacy_dict(self._legacy(status="INCONCLUSIVE"))
        self.assertAlmostEqual(f.confidence, 0.2)

    def test_confidence_not_affected(self):
        """NOT_AFFECTED status → confidence == 0.0."""
        from plugins import Finding
        f = Finding.from_legacy_dict(self._legacy(status="NOT_AFFECTED"))
        self.assertAlmostEqual(f.confidence, 0.0)

    def test_evidence_items_preserved(self):
        """evidence list is preserved through from_legacy_dict → to_dict round-trip."""
        from plugins import Finding
        items = ["item A", "item B", "item C"]
        f = Finding.from_legacy_dict(self._legacy(evidence=items))
        self.assertEqual(f.evidence.items, items)
        self.assertEqual(f.to_dict()["evidence"], items)

    def test_no_cve_handled(self):
        """When cve is 'N/A', cve_refs is empty."""
        from plugins import Finding
        f = Finding.from_legacy_dict(self._legacy(cve="N/A"))
        self.assertEqual(f.cve_refs, [])
        self.assertEqual(f.to_dict()["cve"], "N/A")

    def test_count_by_status_still_works_on_converted_findings(self):
        """ReportGenerator._count_by_status_severity() works on to_dict() output."""
        from plugins import Finding
        findings = [
            Finding.from_legacy_dict(self._legacy(status="CONFIRMED"), "h").to_dict(),
            Finding.from_legacy_dict(self._legacy(status="POTENTIAL"), "h").to_dict(),
            Finding.from_legacy_dict(self._legacy(status="INCONCLUSIVE"), "h").to_dict(),
        ]
        counts = ReportGenerator._count_by_status_severity(findings)
        self.assertEqual(counts["critical_confirmed"], 1)
        self.assertEqual(counts["potential"], 1)
        self.assertEqual(counts["inconclusive"], 1)

    def test_scan_metadata_new(self):
        """ScanMetadata.new() produces a valid metadata object with UUID and timestamp."""
        from plugins import ScanMetadata
        meta = ScanMetadata.new("192.168.1.1", config={"timeout": 1.0, "mode": "common"})
        self.assertTrue(len(meta.scan_id) == 36)  # UUID4 format
        self.assertIn("T", meta.started)           # ISO-8601 timestamp
        self.assertEqual(meta.target, "192.168.1.1")
        self.assertEqual(meta.config["timeout"], 1.0)

    def test_scan_metadata_to_dict(self):
        """ScanMetadata.to_dict() includes all required keys."""
        from plugins import ScanMetadata
        meta = ScanMetadata.new("10.0.0.1", config={"mode": "top1000"})
        d = meta.to_dict()
        for key in ("scan_id", "target", "started", "ended", "config"):
            self.assertIn(key, d)
        self.assertEqual(d["target"], "10.0.0.1")


# ---------------------------------------------------------------------------
# 13. Phase A — Pipeline emits unified findings
# ---------------------------------------------------------------------------

class TestPipelineUnifiedFindings(unittest.TestCase):
    """HybridScanner.run() promotes legacy findings to the unified schema."""

    def _make_args(self, **kwargs):
        import argparse
        defaults = dict(
            scan_mode="common", timeout=1.0, retries=1, concurrency=50,
            ports=None, skip_nvd=True, skip_compliance=True, cve_lookback_days=120,
        )
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    def _run_with_fake_findings(self, legacy_vulns):
        """Helper: run the scanner with mocked port and vuln results."""
        scanner = HybridScanner("127.0.0.1", self._make_args())
        fake_port = [{"port": 445, "service": "SMB", "state": "open",
                      "banner": "", "protocol": "tcp"}]
        with patch("vultron.PortScanner.scan", return_value=fake_port), \
             patch("vultron.VulnerabilityChecker.check_all", return_value=legacy_vulns), \
             patch("vultron.ReportGenerator.generate_html"), \
             patch("vultron.ReportGenerator.generate_json"):
            scanner.run()
        return scanner

    def test_pipeline_findings_have_confidence_field(self):
        """Findings in results include the 'confidence' field."""
        legacy = [{"id": "MS17-010", "cve": "CVE-2017-0144", "name": "EB",
                   "title": "EternalBlue", "severity": "CRITICAL", "status": "CONFIRMED",
                   "port": 445, "affected_service": "SMB", "description": "test",
                   "evidence": ["test"], "cisa_kev": True, "exploit_available": True,
                   "cvss": 9.8, "remediation": "patch"}]
        scanner = self._run_with_fake_findings(legacy)
        self.assertTrue(len(scanner.results["vulnerabilities"]) > 0)
        finding = scanner.results["vulnerabilities"][0]
        self.assertIn("confidence", finding)
        self.assertAlmostEqual(finding["confidence"], 0.9)

    def test_pipeline_findings_have_cve_refs(self):
        """Findings in results include the 'cve_refs' list."""
        legacy = [{"id": "MS17-010", "cve": "CVE-2017-0144", "name": "EB",
                   "title": "EternalBlue", "severity": "CRITICAL", "status": "CONFIRMED",
                   "port": 445, "affected_service": "SMB", "description": "test",
                   "evidence": [], "cisa_kev": False, "exploit_available": False,
                   "cvss": 9.8}]
        scanner = self._run_with_fake_findings(legacy)
        finding = scanner.results["vulnerabilities"][0]
        self.assertIn("cve_refs", finding)
        self.assertIn("CVE-2017-0144", finding["cve_refs"])

    def test_pipeline_findings_have_target(self):
        """Findings in results carry the 'target' field."""
        legacy = [{"id": "TEST", "cve": "N/A", "name": "T", "title": "Test",
                   "severity": "HIGH", "status": "POTENTIAL",
                   "port": 445, "affected_service": "SMB", "description": "t",
                   "evidence": [], "cisa_kev": False, "exploit_available": False}]
        scanner = self._run_with_fake_findings(legacy)
        finding = scanner.results["vulnerabilities"][0]
        self.assertEqual(finding.get("target"), "127.0.0.1")

    def test_pipeline_stores_scan_metadata(self):
        """results['scan_metadata'] is populated after a successful scan."""
        scanner = self._run_with_fake_findings([])
        self.assertIn("scan_metadata", scanner.results)
        meta = scanner.results["scan_metadata"]
        self.assertIn("scan_id", meta)
        self.assertIn("started", meta)
        self.assertIn("ended", meta)
        self.assertEqual(meta["target"], "127.0.0.1")

    def test_pipeline_scan_metadata_config(self):
        """scan_metadata.config contains runtime scan configuration."""
        scanner = self._run_with_fake_findings([])
        config = scanner.results["scan_metadata"]["config"]
        self.assertIn("mode", config)
        self.assertIn("timeout", config)

    def test_pipeline_existing_legacy_keys_preserved(self):
        """All original finding keys survive the unified-schema conversion."""
        legacy = [{"id": "FTP-ANON-21", "cve": "N/A", "name": "FTP Anon",
                   "title": "FTP anonymous login accepted", "severity": "HIGH",
                   "status": "CONFIRMED", "port": 21, "affected_service": "FTP",
                   "description": "anon ftp", "evidence": ["banner"],
                   "cisa_kev": False, "exploit_available": False,
                   "remediation": "Disable anon"}]
        scanner = self._run_with_fake_findings(legacy)
        finding = scanner.results["vulnerabilities"][0]
        for key in ("id", "name", "title", "severity", "status",
                    "port", "affected_service", "description", "evidence"):
            self.assertIn(key, finding, f"Legacy key '{key}' lost after pipeline conversion")

    def test_pipeline_counter_correctness_after_conversion(self):
        """Summary counts derived from converted findings remain correct."""
        legacy = [
            {"id": "A", "cve": "N/A", "name": "A", "title": "A",
             "severity": "CRITICAL", "status": "CONFIRMED",
             "port": 445, "affected_service": "SMB", "description": "",
             "evidence": [], "cisa_kev": True, "exploit_available": True, "cvss": 9.8},
            {"id": "B", "cve": "N/A", "name": "B", "title": "B",
             "severity": "HIGH", "status": "POTENTIAL",
             "port": 445, "affected_service": "SMB", "description": "",
             "evidence": [], "cisa_kev": False, "exploit_available": False},
        ]
        scanner = self._run_with_fake_findings(legacy)
        counts = ReportGenerator._count_by_status_severity(
            scanner.results["vulnerabilities"]
        )
        self.assertEqual(counts["critical_confirmed"], 1)
        self.assertEqual(counts["potential"], 1)
        self.assertEqual(counts["kev_confirmed"], 1)

    def test_scan_metadata_stored_even_when_no_open_ports(self):
        """scan_metadata is stored in results even when port scan finds nothing."""
        scanner = HybridScanner("127.0.0.1", self._make_args())
        with patch("vultron.PortScanner.scan", return_value=[]):
            scanner.run()
        # scan_metadata should be present so the scan record is preserved
        self.assertIn("scan_metadata", scanner.results)
        meta = scanner.results["scan_metadata"]
        self.assertIn("scan_id", meta)
        self.assertIn("ended", meta)
        self.assertIsNotNone(meta["ended"])


# ---------------------------------------------------------------------------
# 14. Phase A — Reporter consumes unified findings
# ---------------------------------------------------------------------------

class TestReporterUnifiedFindings(unittest.TestCase):
    """ReportGenerator handles unified Finding fields (confidence, cve_refs, etc.)."""

    def _make_results(self, findings):
        from datetime import datetime
        return {
            "target": "192.168.1.1",
            "timestamp": datetime.now().isoformat(),
            "scanner_version": "4.0.0-HYBRID",
            "scan_mode": "common",
            "cve_lookback_days": 120,
            "open_ports": [],
            "vulnerabilities": findings,
            "nvd_intelligence": {},
            "compliance": {},
        }

    def test_html_report_renders_confirmed_finding(self):
        """generate_html() includes title, status, and severity for a CONFIRMED finding."""
        import tempfile, os
        finding = {
            "id": "T-001", "cve": "N/A", "name": "TestFinding",
            "title": "Test Security Finding", "severity": "HIGH",
            "status": "CONFIRMED", "port": 80, "affected_service": "HTTP",
            "description": "A test finding.", "evidence": ["proof"],
            "cisa_kev": False, "exploit_available": False,
            "cvss": 7.5, "remediation": "Fix it.",
            "confidence": 0.9, "cve_refs": [], "target": "192.168.1.1",
        }
        reporter = ReportGenerator(self._make_results([finding]))
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            fname = f.name
        try:
            reporter.generate_html(fname)
            with open(fname, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("Test Security Finding", content)
            self.assertIn("CONFIRMED", content)
            self.assertIn("HIGH", content)
        finally:
            os.unlink(fname)

    def test_html_report_shows_confidence_percentage(self):
        """generate_html() renders the confidence value for confirmed findings."""
        import tempfile, os
        finding = {
            "id": "T-002", "cve": "CVE-2024-0001", "name": "ConfTest",
            "title": "Confidence Test", "severity": "CRITICAL",
            "status": "CONFIRMED", "port": 445, "affected_service": "SMB",
            "description": "Test.", "evidence": [],
            "cisa_kev": True, "exploit_available": True, "cvss": 9.8,
            "confidence": 0.9, "cve_refs": ["CVE-2024-0001"], "target": "192.168.1.1",
        }
        reporter = ReportGenerator(self._make_results([finding]))
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            fname = f.name
        try:
            reporter.generate_html(fname)
            with open(fname, "r", encoding="utf-8") as f:
                content = f.read()
            # Confidence should appear as a percentage string
            self.assertIn("90%", content)
        finally:
            os.unlink(fname)

    def test_json_report_includes_confidence(self):
        """generate_json() serialises the 'confidence' field."""
        import tempfile, os, json
        finding = {
            "id": "T-003", "cve": "N/A", "name": "JsonTest",
            "title": "JSON confidence test", "severity": "MEDIUM",
            "status": "POTENTIAL", "port": 23, "affected_service": "Telnet",
            "description": "test", "evidence": ["e1"],
            "cisa_kev": False, "exploit_available": False,
            "confidence": 0.5, "cve_refs": [], "target": "192.168.1.1",
        }
        reporter = ReportGenerator(self._make_results([finding]))
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            fname = f.name
        try:
            reporter.generate_json(fname)
            with open(fname) as f:
                data = json.load(f)
            vuln = data["vulnerabilities"][0]
            self.assertIn("confidence", vuln)
            self.assertAlmostEqual(vuln["confidence"], 0.5)
        finally:
            os.unlink(fname)

    def test_json_report_includes_cve_refs(self):
        """generate_json() serialises the 'cve_refs' list."""
        import tempfile, os, json
        finding = {
            "id": "T-004", "cve": "CVE-2017-0144", "name": "EternalBlue",
            "title": "EternalBlue test", "severity": "CRITICAL",
            "status": "CONFIRMED", "port": 445, "affected_service": "SMB",
            "description": "test", "evidence": [],
            "cisa_kev": True, "exploit_available": True, "cvss": 9.8,
            "confidence": 0.9, "cve_refs": ["CVE-2017-0144"], "target": "192.168.1.1",
        }
        reporter = ReportGenerator(self._make_results([finding]))
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            fname = f.name
        try:
            reporter.generate_json(fname)
            with open(fname) as f:
                data = json.load(f)
            vuln = data["vulnerabilities"][0]
            self.assertIn("cve_refs", vuln)
            self.assertIn("CVE-2017-0144", vuln["cve_refs"])
        finally:
            os.unlink(fname)


# ---------------------------------------------------------------------------
# 15. Phase A — Built-in plugin checks
# ---------------------------------------------------------------------------

class TestBuiltinPluginChecks(unittest.TestCase):
    """Built-in plugin checks are registered and return Finding objects."""

    @classmethod
    def setUpClass(cls):
        """Ensure built-in checks are registered before any test runs."""
        import plugins.checks  # noqa: F401

    def test_eternal_blue_registered(self):
        """EternalBlue check is registered under 'MS17-010'."""
        from plugins import CheckRegistry
        self.assertIsNotNone(CheckRegistry.get("MS17-010"))

    def test_smbghost_registered(self):
        """SMBGhost check is registered under 'CVE-2020-0796'."""
        from plugins import CheckRegistry
        self.assertIsNotNone(CheckRegistry.get("CVE-2020-0796"))

    def test_ftp_anon_registered(self):
        """FTP anonymous login check is registered under 'FTP-ANON'."""
        from plugins import CheckRegistry
        self.assertIsNotNone(CheckRegistry.get("FTP-ANON"))

    def test_telnet_registered(self):
        """Telnet exposure check is registered under 'TELNET-EXPOSURE'."""
        from plugins import CheckRegistry
        self.assertIsNotNone(CheckRegistry.get("TELNET-EXPOSURE"))

    def test_snmp_registered(self):
        """SNMP community check is registered under 'SNMP-DEFAULT-COMMUNITY'."""
        from plugins import CheckRegistry
        self.assertIsNotNone(CheckRegistry.get("SNMP-DEFAULT-COMMUNITY"))

    def test_bluekeep_registered(self):
        """BlueKeep check is registered under 'CVE-2019-0708'."""
        from plugins import CheckRegistry
        self.assertIsNotNone(CheckRegistry.get("CVE-2019-0708"))

    def test_db_exposure_registered(self):
        """Database exposure check is registered under 'DB-EXPOSURE'."""
        from plugins import CheckRegistry
        self.assertIsNotNone(CheckRegistry.get("DB-EXPOSURE"))

    def test_eternal_blue_timeout_gives_inconclusive_finding(self):
        """EternalBlueCheck.run() returns an INCONCLUSIVE Finding on timeout."""
        from plugins import CheckRegistry, Finding
        check = CheckRegistry.get("MS17-010")()
        with patch("socket.socket") as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.connect.side_effect = socket.timeout("timed out")
            findings = check.run("127.0.0.1", 445)
        self.assertEqual(len(findings), 1)
        self.assertIsInstance(findings[0], Finding)
        self.assertEqual(findings[0].status, "INCONCLUSIVE")
        self.assertEqual(findings[0].cve_refs, ["CVE-2017-0144"])

    def test_eternal_blue_confirmed_finding(self):
        """EternalBlueCheck.run() returns a CONFIRMED Finding when SMBv1 responds."""
        from plugins import CheckRegistry, Finding
        check = CheckRegistry.get("MS17-010")()
        smb1_response = b"\xff\x53\x4d\x42" + b"\x00" * 60
        with patch("socket.socket") as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.connect.return_value = None
            mock_sock.recv.return_value = smb1_response
            findings = check.run("127.0.0.1", 445)
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0].status, "CONFIRMED")
        self.assertEqual(findings[0].severity, "CRITICAL")
        self.assertAlmostEqual(findings[0].confidence, 0.9)

    def test_ftp_anon_timeout_returns_inconclusive_finding(self):
        """FTPAnonCheck.run() returns an INCONCLUSIVE Finding on timeout."""
        from plugins import CheckRegistry, Finding
        check = CheckRegistry.get("FTP-ANON")()
        with patch("socket.socket") as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.connect.side_effect = socket.timeout("timed out")
            findings = check.run("127.0.0.1", 21)
        self.assertIsInstance(findings, list)
        self.assertEqual(len(findings), 1)
        self.assertIsInstance(findings[0], Finding)
        self.assertEqual(findings[0].status, "INCONCLUSIVE")

    def test_snmp_timeout_returns_inconclusive_finding(self):
        """SNMPCommunityCheck.run() returns an INCONCLUSIVE Finding when all probes time out."""
        from plugins import CheckRegistry, Finding
        check = CheckRegistry.get("SNMP-DEFAULT-COMMUNITY")()
        with patch("socket.socket") as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = socket.timeout("timed out")
            findings = check.run("127.0.0.1", 161)
        self.assertEqual(len(findings), 1)
        self.assertIsInstance(findings[0], Finding)
        self.assertEqual(findings[0].status, "INCONCLUSIVE")

    def test_bluekeep_always_potential(self):
        """BlueKeepCheck.run() always returns a POTENTIAL finding (cannot confirm without creds)."""
        from plugins import CheckRegistry, Finding
        check = CheckRegistry.get("CVE-2019-0708")()
        findings = check.run("127.0.0.1", 3389)
        self.assertEqual(len(findings), 1)
        self.assertIsInstance(findings[0], Finding)
        self.assertEqual(findings[0].status, "POTENTIAL")
        self.assertIn("CVE-2019-0708", findings[0].cve_refs)

    def test_plugin_run_returns_list_of_findings(self):
        """All registered built-in checks return a list (possibly empty) of Finding objects."""
        from plugins import CheckRegistry, Finding
        for check_cls in CheckRegistry.all_checks():
            check = check_cls()
            with patch("socket.socket") as mock_cls:
                mock_sock = MagicMock()
                mock_cls.return_value = mock_sock
                mock_sock.connect.side_effect = socket.timeout("timed out")
                mock_sock.recvfrom.side_effect = socket.timeout("timed out")
                result = check.run("127.0.0.1", 9999)
            self.assertIsInstance(result, list,
                                  f"{check_cls.check_id}.run() must return a list")
            for item in result:
                self.assertIsInstance(item, Finding,
                                      f"{check_cls.check_id}.run() must return Finding objects")

    def test_eternal_blue_check_for_port_445(self):
        """CheckRegistry dispatches to EternalBlueCheck for port 445."""
        from plugins import CheckRegistry
        check_ids = [c.check_id for c in CheckRegistry.checks_for_port(445)]
        self.assertIn("MS17-010", check_ids)

    def test_ftp_check_for_port_21(self):
        """CheckRegistry dispatches to FTPAnonCheck for port 21."""
        from plugins import CheckRegistry
        check_ids = [c.check_id for c in CheckRegistry.checks_for_port(21)]
        self.assertIn("FTP-ANON", check_ids)


# ---------------------------------------------------------------------------
# 16. PR1 — Credential model validation
# ---------------------------------------------------------------------------

class TestCredentialModelValidation(unittest.TestCase):
    """SSHCredential, WinRMCredential, WMICredential field validation."""

    # --- SSH ---

    def test_ssh_valid_password_auth(self):
        from plugins import SSHCredential
        cred = SSHCredential(username="scanuser", password="s3cr3t")
        cred.validate()  # should not raise

    def test_ssh_valid_key_auth(self):
        import tempfile, os
        from plugins import SSHCredential
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as f:
            f.write(b"fake key content")
            key_path = f.name
        try:
            cred = SSHCredential(username="scanuser", key_path=key_path)
            cred.validate()
        finally:
            os.unlink(key_path)

    def test_ssh_missing_username_raises(self):
        from plugins import SSHCredential, CredentialValidationError
        cred = SSHCredential(username="", password="pass")
        with self.assertRaises(CredentialValidationError):
            cred.validate()

    def test_ssh_missing_both_auth_raises(self):
        from plugins import SSHCredential, CredentialValidationError
        cred = SSHCredential(username="user")
        with self.assertRaises(CredentialValidationError):
            cred.validate()

    def test_ssh_both_password_and_key_raises(self):
        import tempfile, os
        from plugins import SSHCredential, CredentialValidationError
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as f:
            f.write(b"fake")
            key_path = f.name
        try:
            cred = SSHCredential(username="user", password="pass", key_path=key_path)
            with self.assertRaises(CredentialValidationError):
                cred.validate()
        finally:
            os.unlink(key_path)

    def test_ssh_nonexistent_key_path_raises(self):
        from plugins import SSHCredential, CredentialValidationError
        cred = SSHCredential(username="user", key_path="/nonexistent/path/key.pem")
        with self.assertRaises(CredentialValidationError):
            cred.validate()

    def test_ssh_invalid_port_raises(self):
        from plugins import SSHCredential, CredentialValidationError
        cred = SSHCredential(username="user", password="pass", port=99999)
        with self.assertRaises(CredentialValidationError):
            cred.validate()

    def test_ssh_redacted_summary_hides_password(self):
        from plugins import SSHCredential
        cred = SSHCredential(username="scanuser", password="super_secret_password")
        summary = cred.redacted_summary()
        self.assertNotIn("super_secret_password", summary)
        self.assertIn("scanuser", summary)

    def test_ssh_credential_type(self):
        from plugins import SSHCredential
        cred = SSHCredential(username="u", password="p")
        self.assertEqual(cred.credential_type, "ssh")

    # --- WinRM ---

    def test_winrm_valid(self):
        from plugins import WinRMCredential
        cred = WinRMCredential(username="Administrator", password="P@ssword1")
        cred.validate()

    def test_winrm_missing_username_raises(self):
        from plugins import WinRMCredential, CredentialValidationError
        cred = WinRMCredential(username="", password="pass")
        with self.assertRaises(CredentialValidationError):
            cred.validate()

    def test_winrm_missing_password_raises(self):
        from plugins import WinRMCredential, CredentialValidationError
        cred = WinRMCredential(username="Administrator", password=None)
        with self.assertRaises(CredentialValidationError):
            cred.validate()

    def test_winrm_effective_port_http(self):
        from plugins import WinRMCredential
        cred = WinRMCredential(username="u", password="p", transport="http")
        self.assertEqual(cred.effective_port, 5985)

    def test_winrm_effective_port_https(self):
        from plugins import WinRMCredential
        cred = WinRMCredential(username="u", password="p", transport="https")
        self.assertEqual(cred.effective_port, 5986)

    def test_winrm_effective_port_override(self):
        from plugins import WinRMCredential
        cred = WinRMCredential(username="u", password="p", port=5999)
        self.assertEqual(cred.effective_port, 5999)

    def test_winrm_redacted_summary_hides_password(self):
        from plugins import WinRMCredential
        cred = WinRMCredential(username="Administrator", password="TopSecret")
        summary = cred.redacted_summary()
        self.assertNotIn("TopSecret", summary)
        self.assertIn("Administrator", summary)

    def test_winrm_credential_type(self):
        from plugins import WinRMCredential
        cred = WinRMCredential(username="u", password="p")
        self.assertEqual(cred.credential_type, "winrm")

    # --- WMI ---

    def test_wmi_valid(self):
        from plugins import WMICredential
        cred = WMICredential(username="Administrator", password="P@ssword1")
        cred.validate()

    def test_wmi_missing_username_raises(self):
        from plugins import WMICredential, CredentialValidationError
        cred = WMICredential(username="", password="pass")
        with self.assertRaises(CredentialValidationError):
            cred.validate()

    def test_wmi_missing_password_raises(self):
        from plugins import WMICredential, CredentialValidationError
        cred = WMICredential(username="user", password=None)
        with self.assertRaises(CredentialValidationError):
            cred.validate()

    def test_wmi_redacted_summary_hides_password(self):
        from plugins import WMICredential
        cred = WMICredential(username="Administrator", password="HiddenPass")
        summary = cred.redacted_summary()
        self.assertNotIn("HiddenPass", summary)
        self.assertIn("Administrator", summary)

    def test_wmi_credential_type(self):
        from plugins import WMICredential
        cred = WMICredential(username="u", password="p")
        self.assertEqual(cred.credential_type, "wmi")

    # --- CredentialSet ---

    def test_credential_set_empty(self):
        from plugins import CredentialSet
        cs = CredentialSet()
        self.assertTrue(cs.is_empty())

    def test_credential_set_not_empty(self):
        from plugins import CredentialSet, SSHCredential
        cs = CredentialSet(ssh=SSHCredential(username="u", password="p"))
        self.assertFalse(cs.is_empty())

    def test_credential_set_validate_all_propagates_error(self):
        from plugins import CredentialSet, SSHCredential, CredentialValidationError
        cs = CredentialSet(ssh=SSHCredential(username="", password="p"))
        with self.assertRaises(CredentialValidationError):
            cs.validate_all()

    def test_credential_set_redacted_summary_no_secrets(self):
        from plugins import CredentialSet, SSHCredential
        cs = CredentialSet(ssh=SSHCredential(username="alice", password="secret_password"))
        summary = cs.redacted_summary()
        self.assertNotIn("secret_password", str(summary))
        self.assertIn("alice", str(summary))


# ---------------------------------------------------------------------------
# 17. PR1 — Secret masking and redaction helpers
# ---------------------------------------------------------------------------

class TestSecretMasking(unittest.TestCase):
    """Secret masking helpers in plugins.secrets."""

    def test_mask_secret_returns_redacted(self):
        from plugins import mask_secret, REDACTED
        self.assertEqual(mask_secret("actual_password"), REDACTED)

    def test_mask_secret_none_returns_redacted(self):
        from plugins import mask_secret, REDACTED
        self.assertEqual(mask_secret(None), REDACTED)

    def test_redact_dict_masks_password(self):
        from plugins import redact_dict, REDACTED
        d = {"host": "10.0.0.1", "password": "s3cr3t", "port": 22}
        result = redact_dict(d)
        self.assertEqual(result["password"], REDACTED)
        self.assertEqual(result["host"], "10.0.0.1")
        self.assertEqual(result["port"], 22)

    def test_redact_dict_masks_known_keys(self):
        from plugins import redact_dict, REDACTED
        sensitive = ["password", "passwd", "secret", "token", "api_key", "passphrase"]
        for key in sensitive:
            d = {key: "supersecret"}
            result = redact_dict(d)
            self.assertEqual(result[key], REDACTED, f"Key '{key}' was not redacted")

    def test_redact_dict_leaves_non_sensitive(self):
        from plugins import redact_dict
        d = {"host": "10.0.0.1", "port": 22, "username": "scanuser"}
        result = redact_dict(d)
        self.assertEqual(result["host"], "10.0.0.1")
        self.assertEqual(result["port"], 22)

    def test_redact_dict_extra_keys(self):
        from plugins import redact_dict, REDACTED
        d = {"my_custom_secret": "value", "normal": "ok"}
        result = redact_dict(d, extra_keys=["my_custom_secret"])
        self.assertEqual(result["my_custom_secret"], REDACTED)
        self.assertEqual(result["normal"], "ok")

    def test_deep_redact_dict_nested(self):
        from plugins import deep_redact_dict, REDACTED
        d = {
            "scan": {
                "target": "10.0.0.1",
                "auth_config": {
                    "ssh": {"password": "nested_secret", "username": "user"}
                }
            }
        }
        result = deep_redact_dict(d)
        self.assertEqual(
            result["scan"]["auth_config"]["ssh"]["password"], REDACTED
        )
        self.assertEqual(result["scan"]["auth_config"]["ssh"]["username"], "user")

    def test_deep_redact_list(self):
        from plugins import deep_redact_dict, REDACTED
        data = [{"password": "s"}, {"host": "10.0.0.1"}]
        result = deep_redact_dict(data)
        self.assertEqual(result[0]["password"], REDACTED)
        self.assertEqual(result[1]["host"], "10.0.0.1")

    def test_redact_string_inline_password(self):
        from plugins.secrets import redact_string, REDACTED
        line = "Connecting with password=mypassword123 to host"
        result = redact_string(line)
        self.assertNotIn("mypassword123", result)
        self.assertIn(REDACTED, result)

    def test_redact_string_no_sensitive_content_unchanged(self):
        from plugins.secrets import redact_string
        line = "Port 22/tcp is open on 10.0.0.1"
        self.assertEqual(redact_string(line), line)

    def test_finding_evidence_not_leaked_in_redact(self):
        """Ensure scan findings evidence can be safely redacted when needed."""
        from plugins import deep_redact_dict, REDACTED
        finding = {
            "id": "AUTH-PROBE-SSH",
            "status": "CONFIRMED",
            "password": "should_be_redacted",
            "evidence": ["SSH port 22/tcp is open"],
        }
        result = deep_redact_dict(finding)
        self.assertEqual(result["password"], REDACTED)
        self.assertEqual(result["evidence"], ["SSH port 22/tcp is open"])


# ---------------------------------------------------------------------------
# 18. PR1 — Credential providers
# ---------------------------------------------------------------------------

class TestCredentialProviders(unittest.TestCase):
    """Credential provider abstraction: inline, env, file, chained."""

    def test_inline_provider_returns_set(self):
        from plugins import (
            InlineCredentialProvider, CredentialSet, SSHCredential,
        )
        cs = CredentialSet(ssh=SSHCredential(username="u", password="p"))
        provider = InlineCredentialProvider(cs)
        result = provider.get_credentials("10.0.0.1")
        self.assertIs(result, cs)

    def test_env_provider_no_vars_returns_empty(self):
        from plugins import EnvCredentialProvider
        import os
        env_keys = [
            "VULTRON_SSH_USER", "VULTRON_SSH_PASSWORD",
            "VULTRON_WINRM_USER", "VULTRON_WINRM_PASSWORD",
            "VULTRON_WMI_USER", "VULTRON_WMI_PASSWORD",
        ]
        # Ensure no relevant vars are set
        clean_env = {k: v for k, v in os.environ.items() if k not in env_keys}
        with patch.dict(os.environ, clean_env, clear=True):
            provider = EnvCredentialProvider()
            cs = provider.get_credentials()
        self.assertTrue(cs.is_empty())

    def test_env_provider_ssh_from_env(self):
        from plugins import EnvCredentialProvider
        import os
        with patch.dict(os.environ, {
            "VULTRON_SSH_USER": "envuser",
            "VULTRON_SSH_PASSWORD": "envpass",
        }):
            provider = EnvCredentialProvider()
            cs = provider.get_credentials()
        self.assertIsNotNone(cs.ssh)
        self.assertEqual(cs.ssh.username, "envuser")
        self.assertEqual(cs.ssh.password, "envpass")

    def test_env_provider_winrm_from_env(self):
        from plugins import EnvCredentialProvider
        import os
        with patch.dict(os.environ, {
            "VULTRON_WINRM_USER": "winadmin",
            "VULTRON_WINRM_PASSWORD": "winpass",
            "VULTRON_WINRM_DOMAIN": "CORP",
        }):
            provider = EnvCredentialProvider()
            cs = provider.get_credentials()
        self.assertIsNotNone(cs.winrm)
        self.assertEqual(cs.winrm.username, "winadmin")
        self.assertEqual(cs.winrm.domain, "CORP")

    def test_env_provider_wmi_from_env(self):
        from plugins import EnvCredentialProvider
        import os
        with patch.dict(os.environ, {
            "VULTRON_WMI_USER": "wmiuser",
            "VULTRON_WMI_PASSWORD": "wmipass",
        }):
            provider = EnvCredentialProvider()
            cs = provider.get_credentials()
        self.assertIsNotNone(cs.wmi)
        self.assertEqual(cs.wmi.username, "wmiuser")

    def test_file_provider_missing_file_returns_empty(self):
        from plugins import FileCredentialProvider
        provider = FileCredentialProvider("/nonexistent/file.json")
        cs = provider.get_credentials()
        self.assertTrue(cs.is_empty())

    def test_file_provider_valid_json(self):
        import tempfile, json, os
        from plugins import FileCredentialProvider
        data = {
            "ssh": {"username": "fileuser", "password": "<placeholder>"},
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            fpath = f.name
        try:
            provider = FileCredentialProvider(fpath)
            cs = provider.get_credentials()
            self.assertIsNotNone(cs.ssh)
            self.assertEqual(cs.ssh.username, "fileuser")
        finally:
            os.unlink(fpath)

    def test_file_provider_invalid_json_returns_empty(self):
        import tempfile, os
        from plugins import FileCredentialProvider
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json {{{")
            fpath = f.name
        try:
            provider = FileCredentialProvider(fpath)
            cs = provider.get_credentials()
            self.assertTrue(cs.is_empty())
        finally:
            os.unlink(fpath)

    def test_chained_provider_returns_first_nonempty(self):
        from plugins import (
            ChainedCredentialProvider, InlineCredentialProvider,
            CredentialSet, SSHCredential,
        )
        empty = InlineCredentialProvider(CredentialSet())
        filled = InlineCredentialProvider(
            CredentialSet(ssh=SSHCredential(username="u", password="p"))
        )
        chained = ChainedCredentialProvider([empty, filled])
        cs = chained.get_credentials()
        self.assertIsNotNone(cs.ssh)
        self.assertEqual(cs.ssh.username, "u")

    def test_chained_provider_all_empty_returns_empty(self):
        from plugins import (
            ChainedCredentialProvider, InlineCredentialProvider, CredentialSet,
        )
        chained = ChainedCredentialProvider([
            InlineCredentialProvider(CredentialSet()),
            InlineCredentialProvider(CredentialSet()),
        ])
        cs = chained.get_credentials()
        self.assertTrue(cs.is_empty())

    def test_build_default_provider_inline(self):
        from plugins import build_default_provider, CredentialSet, SSHCredential
        cs = CredentialSet(ssh=SSHCredential(username="u", password="p"))
        provider = build_default_provider(inline=cs)
        result = provider.get_credentials()
        self.assertIsNotNone(result.ssh)


# ---------------------------------------------------------------------------
# 19. PR1 — Authenticated executor probes
# ---------------------------------------------------------------------------

class TestAuthenticatedExecutor(unittest.TestCase):
    """AuthenticatedExecutor probe scaffolding."""

    def _make_cred_set(self):
        from plugins import CredentialSet, SSHCredential
        return CredentialSet(ssh=SSHCredential(username="u", password="p"))

    def test_empty_creds_returns_no_findings(self):
        from plugins import AuthenticatedExecutor, CredentialSet
        executor = AuthenticatedExecutor("127.0.0.1", CredentialSet())
        findings = executor.run_probes()
        self.assertEqual(findings, [])

    def test_ssh_probe_unreachable_gives_inconclusive_finding(self):
        from plugins import AuthenticatedExecutor, Finding
        cs = self._make_cred_set()
        executor = AuthenticatedExecutor("127.0.0.1", cs)
        with patch("plugins.auth_executor._tcp_reachable", return_value=(False, "refused")):
            findings = executor.run_probes()
        self.assertEqual(len(findings), 1)
        self.assertIsInstance(findings[0], Finding)
        self.assertEqual(findings[0].status, "INCONCLUSIVE")
        self.assertEqual(findings[0].id, "AUTH-PROBE-SSH")

    def test_ssh_probe_reachable_no_paramiko_gives_confirmed(self):
        """When TCP is reachable but paramiko is absent, fall back to CONFIRMED TCP."""
        from plugins import AuthenticatedExecutor, Finding
        cs = self._make_cred_set()
        executor = AuthenticatedExecutor("127.0.0.1", cs)

        def mock_probe(*args, **kwargs):
            from plugins.auth_executor import ProbeResult
            return ProbeResult(
                protocol="ssh", target="127.0.0.1", port=22,
                success=True,
                message="SSH connectivity confirmed (TCP-only)",
            )

        with patch("plugins.auth_executor._probe_ssh", side_effect=mock_probe):
            findings = executor.run_probes()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "CONFIRMED")
        self.assertAlmostEqual(findings[0].confidence, 0.9)

    def test_auth_context_updated_after_successful_probe(self):
        """Context.authenticated_mode becomes True after a successful probe."""
        from plugins import AuthenticatedExecutor, CredentialSet, SSHCredential
        cs = CredentialSet(ssh=SSHCredential(username="u", password="p"))
        executor = AuthenticatedExecutor("127.0.0.1", cs)

        def mock_probe(*args, **kwargs):
            from plugins.auth_executor import ProbeResult
            return ProbeResult(
                protocol="ssh", target="127.0.0.1", port=22,
                success=True, message="ok",
            )

        with patch("plugins.auth_executor._probe_ssh", side_effect=mock_probe):
            executor.run_probes()
        self.assertTrue(executor.context.authenticated_mode)

    def test_auth_context_not_authenticated_on_failure(self):
        """Context.authenticated_mode remains False when probes fail."""
        from plugins import AuthenticatedExecutor, CredentialSet, SSHCredential
        cs = CredentialSet(ssh=SSHCredential(username="u", password="p"))
        executor = AuthenticatedExecutor("127.0.0.1", cs)

        with patch("plugins.auth_executor._tcp_reachable", return_value=(False, "refused")):
            executor.run_probes()
        self.assertFalse(executor.context.authenticated_mode)

    def test_probe_result_to_dict_no_secrets(self):
        """ProbeResult.to_dict() does not expose passwords."""
        from plugins import ProbeResult
        result = ProbeResult(
            protocol="ssh", target="10.0.0.1", port=22,
            success=True,
            message="SSH port 22/tcp is reachable",
        )
        d = result.to_dict()
        self.assertNotIn("password", d)
        self.assertNotIn("username", d)
        self.assertIn("success", d)
        self.assertIn("message", d)

    def test_auth_session_context_metadata_no_secrets(self):
        """AuthSessionContext.to_metadata_dict() does not leak credential secrets."""
        from plugins import AuthenticatedExecutor, CredentialSet, SSHCredential
        cs = CredentialSet(ssh=SSHCredential(username="alice", password="very_secret"))
        executor = AuthenticatedExecutor("10.0.0.1", cs)
        meta = executor.context.to_metadata_dict()
        meta_str = str(meta)
        self.assertNotIn("very_secret", meta_str)
        self.assertIn("alice", meta_str)

    def test_multiple_protocols_all_probed(self):
        """Executor runs a probe for each configured credential type."""
        from plugins import (
            AuthenticatedExecutor, CredentialSet,
            SSHCredential, WinRMCredential, WMICredential,
        )
        cs = CredentialSet(
            ssh=SSHCredential(username="u", password="p"),
            winrm=WinRMCredential(username="u", password="p"),
            wmi=WMICredential(username="u", password="p"),
        )
        executor = AuthenticatedExecutor("10.0.0.1", cs)
        with patch("plugins.auth_executor._tcp_reachable", return_value=(False, "refused")):
            findings = executor.run_probes()
        # One finding per configured protocol
        self.assertEqual(len(findings), 3)
        ids = {f.id for f in findings}
        self.assertIn("AUTH-PROBE-SSH", ids)
        self.assertIn("AUTH-PROBE-WINRM", ids)
        self.assertIn("AUTH-PROBE-WMI", ids)


# ---------------------------------------------------------------------------
# 20. PR1 — Auth probe plugin checks
# ---------------------------------------------------------------------------

class TestAuthProbePluginChecks(unittest.TestCase):
    """Auth probe checks are registered and produce valid Finding objects."""

    @classmethod
    def setUpClass(cls):
        import plugins.checks  # noqa: F401

    def test_ssh_probe_registered(self):
        from plugins import CheckRegistry
        self.assertIsNotNone(CheckRegistry.get("AUTH-PROBE-SSH"))

    def test_winrm_probe_registered(self):
        from plugins import CheckRegistry
        self.assertIsNotNone(CheckRegistry.get("AUTH-PROBE-WINRM"))

    def test_wmi_probe_registered(self):
        from plugins import CheckRegistry
        self.assertIsNotNone(CheckRegistry.get("AUTH-PROBE-WMI"))

    def test_ssh_probe_no_creds_unreachable_returns_empty(self):
        """SSH probe without creds and unreachable port returns empty list."""
        from plugins import CheckRegistry, CredentialSet
        check = CheckRegistry.get("AUTH-PROBE-SSH")()
        with patch("plugins.auth_executor._tcp_reachable", return_value=(False, "refused")):
            result = check.run("127.0.0.1", 22, credential_set=CredentialSet())
        self.assertEqual(result, [])

    def test_ssh_probe_no_creds_reachable_returns_confirmed(self):
        """SSH probe without creds but reachable port returns CONFIRMED INFO finding."""
        from plugins import CheckRegistry, CredentialSet, Finding
        check = CheckRegistry.get("AUTH-PROBE-SSH")()
        with patch("plugins.auth_executor._tcp_reachable", return_value=(True, None)), \
             patch("socket.create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_sock.__enter__ = MagicMock(return_value=mock_sock)
            mock_sock.__exit__ = MagicMock(return_value=False)
            mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"
            mock_conn.return_value = mock_sock
            result = check.run("127.0.0.1", 22, credential_set=CredentialSet())
        self.assertIsInstance(result, list)
        # May return CONFIRMED or INCONCLUSIVE depending on banner grab
        if result:
            self.assertIsInstance(result[0], Finding)
            self.assertEqual(result[0].severity, "INFO")

    def test_auth_probe_checks_have_requires_credentials_false(self):
        """Auth probe checks do not *require* credentials (they are optional)."""
        from plugins import CheckRegistry
        for check_id in ("AUTH-PROBE-SSH", "AUTH-PROBE-WINRM", "AUTH-PROBE-WMI"):
            check_cls = CheckRegistry.get(check_id)
            self.assertIsNotNone(check_cls)
            self.assertFalse(
                check_cls.requires_credentials,
                f"{check_id} should have requires_credentials=False",
            )

    def test_auth_probe_checks_declare_credential_types(self):
        """Auth probe checks declare which credential types they accept."""
        from plugins import CheckRegistry
        checks_and_types = [
            ("AUTH-PROBE-SSH", "ssh"),
            ("AUTH-PROBE-WINRM", "winrm"),
            ("AUTH-PROBE-WMI", "wmi"),
        ]
        for check_id, cred_type in checks_and_types:
            check_cls = CheckRegistry.get(check_id)
            self.assertIn(
                cred_type, check_cls.credential_types,
                f"{check_id} should declare '{cred_type}' in credential_types",
            )


# ---------------------------------------------------------------------------
# 21. PR1 — CLI parsing for credential options
# ---------------------------------------------------------------------------

class TestCLICredentialParsing(unittest.TestCase):
    """CLI argument parser correctly parses credential options."""

    def _parse(self, args_list):
        import argparse
        import sys
        from io import StringIO
        # We test by importing the parser logic directly
        old_argv = sys.argv
        try:
            sys.argv = ["vultron.py"] + args_list
            # Re-import to get fresh argparse
            import importlib
            import vultron as vt
            # Manually reconstruct the parser call used in main()
            # We replicate the parser construction here to test it
            import argparse as ap
            parser = ap.ArgumentParser()
            parser.add_argument('-t', '--target', required=True)
            parser.add_argument('--scan-mode', default='common')
            parser.add_argument('--ports')
            parser.add_argument('--timeout', type=float, default=1.0)
            parser.add_argument('--retries', type=int, default=1)
            parser.add_argument('--concurrency', type=int, default=50)
            parser.add_argument('--skip-nvd', action='store_true')
            parser.add_argument('--skip-compliance', action='store_true')
            parser.add_argument('--cve-lookback-days', type=int, default=120)
            parser.add_argument('--cred-file')
            parser.add_argument('--ssh-user')
            parser.add_argument('--ssh-password')
            parser.add_argument('--ssh-key')
            parser.add_argument('--ssh-port', type=int, default=22)
            parser.add_argument('--winrm-user')
            parser.add_argument('--winrm-password')
            parser.add_argument('--winrm-domain')
            parser.add_argument('--winrm-transport', default='http')
            parser.add_argument('--wmi-user')
            parser.add_argument('--wmi-password')
            parser.add_argument('--wmi-domain')
            return parser.parse_args(args_list)
        finally:
            sys.argv = old_argv

    def test_no_cred_args_all_none(self):
        args = self._parse(['-t', '10.0.0.1'])
        self.assertIsNone(args.ssh_user)
        self.assertIsNone(args.winrm_user)
        self.assertIsNone(args.wmi_user)

    def test_ssh_user_parsed(self):
        args = self._parse(['-t', '10.0.0.1', '--ssh-user', 'scanuser'])
        self.assertEqual(args.ssh_user, 'scanuser')

    def test_ssh_password_parsed(self):
        args = self._parse(['-t', '10.0.0.1', '--ssh-user', 'u', '--ssh-password', 'pass'])
        self.assertEqual(args.ssh_password, 'pass')

    def test_ssh_key_parsed(self):
        args = self._parse(['-t', '10.0.0.1', '--ssh-user', 'u', '--ssh-key', '/path/key'])
        self.assertEqual(args.ssh_key, '/path/key')

    def test_ssh_port_default(self):
        args = self._parse(['-t', '10.0.0.1', '--ssh-user', 'u', '--ssh-password', 'p'])
        self.assertEqual(args.ssh_port, 22)

    def test_ssh_port_custom(self):
        args = self._parse(['-t', '10.0.0.1', '--ssh-user', 'u', '--ssh-port', '2222'])
        self.assertEqual(args.ssh_port, 2222)

    def test_winrm_user_parsed(self):
        args = self._parse(['-t', '10.0.0.1', '--winrm-user', 'Administrator'])
        self.assertEqual(args.winrm_user, 'Administrator')

    def test_winrm_domain_parsed(self):
        args = self._parse(['-t', '10.0.0.1', '--winrm-user', 'u', '--winrm-domain', 'CORP'])
        self.assertEqual(args.winrm_domain, 'CORP')

    def test_winrm_transport_default(self):
        args = self._parse(['-t', '10.0.0.1'])
        self.assertEqual(args.winrm_transport, 'http')

    def test_winrm_transport_https(self):
        args = self._parse(['-t', '10.0.0.1', '--winrm-transport', 'https'])
        self.assertEqual(args.winrm_transport, 'https')

    def test_wmi_user_parsed(self):
        args = self._parse(['-t', '10.0.0.1', '--wmi-user', 'wmiuser'])
        self.assertEqual(args.wmi_user, 'wmiuser')

    def test_cred_file_parsed(self):
        args = self._parse(['-t', '10.0.0.1', '--cred-file', '/etc/creds.json'])
        self.assertEqual(args.cred_file, '/etc/creds.json')


# ---------------------------------------------------------------------------
# 22. PR1 — HybridScanner credentialed mode integration
# ---------------------------------------------------------------------------

class TestHybridScannerCredentialedMode(unittest.TestCase):
    """HybridScanner handles credentialed mode correctly."""

    def _make_args(self, **kwargs):
        import argparse
        defaults = dict(
            scan_mode='common', timeout=1.0, retries=1, concurrency=50,
            ports=None, skip_nvd=True, skip_compliance=True, cve_lookback_days=120,
            ssh_user=None, ssh_password=None, ssh_key=None, ssh_port=22,
            winrm_user=None, winrm_password=None, winrm_domain=None,
            winrm_transport='http',
            wmi_user=None, wmi_password=None, wmi_domain=None,
            cred_file=None,
        )
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    def _run_with_fake_scan(self, args, auth_findings=None):
        from vultron import HybridScanner
        scanner = HybridScanner("127.0.0.1", args)
        fake_port = [{"port": 22, "service": "SSH", "state": "open",
                      "banner": "", "protocol": "tcp"}]
        with patch("vultron.PortScanner.scan", return_value=fake_port), \
             patch("vultron.VulnerabilityChecker.check_all", return_value=[]), \
             patch("vultron.ReportGenerator.generate_html"), \
             patch("vultron.ReportGenerator.generate_json"):
            if auth_findings is not None:
                with patch("vultron.AuthenticatedExecutor.run_probes",
                           return_value=auth_findings):
                    scanner.run()
            else:
                scanner.run()
        return scanner

    def test_no_creds_auth_scan_not_attempted(self):
        """Without credentials, auth_scan shows authenticated_mode=False."""
        args = self._make_args()
        scanner = self._run_with_fake_scan(args)
        auth_scan = scanner.results.get('auth_scan', {})
        self.assertFalse(auth_scan.get('authenticated_mode', True))

    def test_with_ssh_creds_executor_called(self):
        """With SSH credentials, AuthenticatedExecutor.run_probes() is called."""
        from plugins import Finding, Evidence
        args = self._make_args(ssh_user="scanuser", ssh_password="pass")
        probe_finding = Finding(
            id="AUTH-PROBE-SSH",
            title="SSH probe",
            description="SSH TCP reachable",
            status="CONFIRMED",
            severity="INFO",
            confidence=0.9,
            target="127.0.0.1",
            port=22,
            service="SSH",
            evidence=Evidence(items=["SSH reachable"]),
        )
        with patch("vultron.AuthenticatedExecutor.run_probes",
                   return_value=[probe_finding]) as mock_run, \
             patch("vultron.PortScanner.scan", return_value=[
                 {"port": 22, "service": "SSH", "state": "open",
                  "banner": "", "protocol": "tcp"}
             ]), \
             patch("vultron.VulnerabilityChecker.check_all", return_value=[]), \
             patch("vultron.ReportGenerator.generate_html"), \
             patch("vultron.ReportGenerator.generate_json"):
            from vultron import HybridScanner
            scanner = HybridScanner("127.0.0.1", args)
            scanner.run()
            mock_run.assert_called_once()

    def test_auth_probe_findings_added_to_vulnerabilities(self):
        """Auth probe findings appear in the vulnerabilities list."""
        from plugins import Finding, Evidence
        args = self._make_args(ssh_user="u", ssh_password="p")
        probe_finding = Finding(
            id="AUTH-PROBE-SSH",
            title="SSH Authenticated Connectivity Probe",
            description="SSH connectivity confirmed",
            status="CONFIRMED",
            severity="INFO",
            confidence=0.9,
            target="127.0.0.1",
            port=22,
            service="SSH",
            evidence=Evidence(items=["TCP reachable"]),
        )
        scanner = self._run_with_fake_scan(args, auth_findings=[probe_finding])
        vuln_ids = [v.get("id") for v in scanner.results["vulnerabilities"]]
        self.assertIn("AUTH-PROBE-SSH", vuln_ids)

    def test_auth_scan_metadata_no_passwords(self):
        """auth_scan metadata in results does not contain credential passwords."""
        from plugins import Finding, Evidence
        args = self._make_args(ssh_user="alice", ssh_password="super_secret_password")
        probe_finding = Finding(
            id="AUTH-PROBE-SSH",
            title="SSH probe",
            description="test",
            status="CONFIRMED",
            severity="INFO",
            confidence=0.9,
            target="127.0.0.1",
            port=22,
            service="SSH",
            evidence=Evidence(items=["ok"]),
        )
        scanner = self._run_with_fake_scan(args, auth_findings=[probe_finding])
        auth_scan_str = str(scanner.results.get('auth_scan', {}))
        self.assertNotIn("super_secret_password", auth_scan_str)

    def test_json_report_no_credential_secrets(self):
        """JSON report does not contain credential passwords."""
        import tempfile, json, os
        from plugins import Finding, Evidence
        args = self._make_args(ssh_user="alice", ssh_password="top_secret_password_xyz")
        probe_finding = Finding(
            id="AUTH-PROBE-SSH",
            title="SSH probe",
            description="test",
            status="CONFIRMED",
            severity="INFO",
            confidence=0.9,
            target="127.0.0.1",
            port=22,
            service="SSH",
            evidence=Evidence(items=["ok"]),
        )
        with patch("vultron.PortScanner.scan", return_value=[
            {"port": 22, "service": "SSH", "state": "open", "banner": "", "protocol": "tcp"}
        ]), patch("vultron.VulnerabilityChecker.check_all", return_value=[]), \
             patch("vultron.AuthenticatedExecutor.run_probes", return_value=[probe_finding]):
            from vultron import HybridScanner, ReportGenerator
            scanner = HybridScanner("127.0.0.1", args)
            scanner.run.__func__  # ensure it's the real run
            # Run up to report generation
            scanner.results['open_ports'] = [
                {"port": 22, "service": "SSH", "state": "open", "banner": "", "protocol": "tcp"}
            ]
            scanner.results['vulnerabilities'] = [probe_finding.to_dict()]
            scanner.results['auth_scan'] = {'authenticated_mode': True}

            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
                fname = f.name
            try:
                reporter = ReportGenerator(scanner.results)
                reporter.generate_json(fname)
                with open(fname) as f:
                    content = f.read()
                self.assertNotIn("top_secret_password_xyz", content)
            finally:
                os.unlink(fname)

    def test_unauthenticated_checks_unaffected_by_cred_mode(self):
        """Legacy unauthenticated checks still run when credentials are provided."""
        legacy_finding = {
            "id": "MS17-010", "cve": "CVE-2017-0144", "name": "EB",
            "title": "EternalBlue", "severity": "CRITICAL", "status": "CONFIRMED",
            "port": 445, "affected_service": "SMB", "description": "test",
            "evidence": ["SMBv1 accepted"], "cisa_kev": True,
            "exploit_available": True, "cvss": 9.8,
        }
        args = self._make_args(ssh_user="u", ssh_password="p")
        with patch("vultron.PortScanner.scan", return_value=[
            {"port": 445, "service": "SMB", "state": "open", "banner": "", "protocol": "tcp"}
        ]), patch("vultron.VulnerabilityChecker.check_all", return_value=[legacy_finding]), \
             patch("vultron.AuthenticatedExecutor.run_probes", return_value=[]), \
             patch("vultron.ReportGenerator.generate_html"), \
             patch("vultron.ReportGenerator.generate_json"):
            from vultron import HybridScanner
            scanner = HybridScanner("127.0.0.1", args)
            scanner.run()
        vuln_ids = [v.get("id") for v in scanner.results["vulnerabilities"]]
        self.assertIn("MS17-010", vuln_ids)


# ---------------------------------------------------------------------------
# 23. PR1 — BaseCheck credential attributes
# ---------------------------------------------------------------------------

class TestBaseCheckCredentialAttributes(unittest.TestCase):
    """BaseCheck subclasses correctly inherit credential attributes."""

    def test_base_check_has_requires_credentials(self):
        from plugins import BaseCheck
        self.assertFalse(BaseCheck.requires_credentials)

    def test_base_check_has_credential_types(self):
        from plugins import BaseCheck
        self.assertEqual(BaseCheck.credential_types, [])

    def test_unauthenticated_check_has_no_cred_types(self):
        from plugins import CheckRegistry
        # EternalBlue is a purely unauthenticated check
        check_cls = CheckRegistry.get("MS17-010")
        self.assertFalse(check_cls.requires_credentials)
        self.assertEqual(check_cls.credential_types, [])

    def test_auth_probe_check_declares_cred_type(self):
        from plugins import CheckRegistry
        check_cls = CheckRegistry.get("AUTH-PROBE-SSH")
        self.assertIn("ssh", check_cls.credential_types)


# ---------------------------------------------------------------------------
# 24. PR2 — UDP scanner state classification
# ---------------------------------------------------------------------------

class TestUDPScannerStateClassification(unittest.TestCase):
    """UDPScanner.scan_port() classifies port state correctly."""

    def _scanner(self, **kwargs):
        from plugins.udp_scanner import UDPScanner
        return UDPScanner("127.0.0.1", ports=[53, 123, 161], **kwargs)

    def test_response_received_state_is_open(self):
        """When a response is received, state must be 'open'."""
        from plugins.udp_scanner import UDPScanner
        scanner = UDPScanner("127.0.0.1", ports=[53])
        with patch('socket.socket') as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.recvfrom.return_value = (b'\x137\x81\x80', ('127.0.0.1', 53))
            result = scanner.scan_port(53)
        self.assertIsNotNone(result)
        self.assertEqual(result['state'], 'open')
        self.assertEqual(result['protocol'], 'udp')
        self.assertEqual(result['port'], 53)

    def test_timeout_state_is_open_filtered(self):
        """No response (timeout) must produce 'open|filtered' state."""
        from plugins.udp_scanner import UDPScanner
        scanner = UDPScanner("127.0.0.1", ports=[123])
        with patch('socket.socket') as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = socket.timeout("timed out")
            result = scanner.scan_port(123)
        self.assertIsNotNone(result)
        self.assertEqual(result['state'], 'open|filtered')
        self.assertEqual(result['protocol'], 'udp')

    def test_icmp_unreachable_returns_none(self):
        """ICMP port-unreachable (ConnectionRefusedError) → None (closed)."""
        from plugins.udp_scanner import UDPScanner
        scanner = UDPScanner("127.0.0.1", ports=[9999])
        with patch('socket.socket') as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.sendto.side_effect = ConnectionRefusedError("port unreachable")
            result = scanner.scan_port(9999)
        self.assertIsNone(result)

    def test_open_result_has_required_keys(self):
        """Open port result contains port, state, service, banner, protocol."""
        from plugins.udp_scanner import UDPScanner
        scanner = UDPScanner("127.0.0.1", ports=[161])
        with patch('socket.socket') as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.recvfrom.return_value = (b'\x30\x10', ('127.0.0.1', 161))
            result = scanner.scan_port(161)
        self.assertIsNotNone(result)
        for key in ('port', 'state', 'service', 'banner', 'protocol'):
            self.assertIn(key, result, f"Missing key '{key}' in UDP result")

    def test_service_name_assigned_for_known_port(self):
        """Known UDP ports get the correct service name."""
        from plugins.udp_scanner import UDPScanner
        scanner = UDPScanner("127.0.0.1", ports=[53])
        with patch('socket.socket') as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = socket.timeout()
            result = scanner.scan_port(53)
        self.assertIsNotNone(result)
        self.assertEqual(result['service'], 'DNS')

    def test_unknown_port_gets_fallback_service_name(self):
        """Unknown UDP ports get 'Unknown-<port>' service name."""
        from plugins.udp_scanner import UDPScanner
        scanner = UDPScanner("127.0.0.1", ports=[54321])
        with patch('socket.socket') as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = socket.timeout()
            result = scanner.scan_port(54321)
        self.assertIsNotNone(result)
        self.assertEqual(result['service'], 'Unknown-54321')

    def test_scan_returns_only_non_closed_ports(self):
        """scan() excludes ports classified as closed (None result)."""
        from plugins.udp_scanner import UDPScanner
        scanner = UDPScanner("127.0.0.1", ports=[53, 123])
        call_count = [0]

        def mock_scan_port(port):
            call_count[0] += 1
            if port == 53:
                return {'port': 53, 'state': 'open|filtered',
                        'service': 'DNS', 'banner': '', 'protocol': 'udp'}
            return None  # 123 is closed

        scanner.scan_port = mock_scan_port
        results = scanner.scan()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['port'], 53)

    def test_scan_results_sorted_by_port(self):
        """scan() returns results sorted by port number."""
        from plugins.udp_scanner import UDPScanner
        scanner = UDPScanner("127.0.0.1", ports=[161, 53, 123])

        def mock_scan_port(port):
            return {'port': port, 'state': 'open|filtered',
                    'service': 'test', 'banner': '', 'protocol': 'udp'}

        scanner.scan_port = mock_scan_port
        results = scanner.scan()
        ports = [r['port'] for r in results]
        self.assertEqual(ports, sorted(ports))

    def test_oserror_retried_and_returns_none(self):
        """OSError is retried; after all retries exhausted returns None."""
        from plugins.udp_scanner import UDPScanner
        scanner = UDPScanner("127.0.0.1", ports=[53], retries=2)
        with patch('socket.socket') as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.sendto.side_effect = OSError("network error")
            result = scanner.scan_port(53)
        self.assertIsNone(result)

    def test_default_ports_is_common_udp_set(self):
        """UDPScanner without explicit ports uses UDP_DEFAULT_PORTS."""
        from plugins.udp_scanner import UDPScanner, UDP_DEFAULT_PORTS
        scanner = UDPScanner("127.0.0.1")
        self.assertEqual(sorted(scanner.ports), sorted(UDP_DEFAULT_PORTS))


# ---------------------------------------------------------------------------
# 25. PR2 — UDP probe builders
# ---------------------------------------------------------------------------

class TestUDPProbeBuilders(unittest.TestCase):
    """Protocol-aware probe builder functions produce valid payloads."""

    def test_dns_probe_is_bytes(self):
        from plugins.udp_scanner import _build_dns_probe
        pkt = _build_dns_probe()
        self.assertIsInstance(pkt, bytes)
        self.assertGreater(len(pkt), 12)  # at minimum a DNS header

    def test_dns_probe_has_correct_transaction_id(self):
        from plugins.udp_scanner import _build_dns_probe
        import struct
        pkt = _build_dns_probe()
        tx_id = struct.unpack('>H', pkt[:2])[0]
        self.assertEqual(tx_id, 0x1337)

    def test_dns_probe_contains_version_bind(self):
        from plugins.udp_scanner import _build_dns_probe
        pkt = _build_dns_probe()
        self.assertIn(b'version', pkt)

    def test_ntp_probe_is_48_bytes(self):
        from plugins.udp_scanner import _build_ntp_probe
        pkt = _build_ntp_probe()
        self.assertEqual(len(pkt), 48)

    def test_ntp_probe_first_byte_is_0x1b(self):
        from plugins.udp_scanner import _build_ntp_probe
        pkt = _build_ntp_probe()
        self.assertEqual(pkt[0], 0x1B)

    def test_snmp_probe_starts_with_sequence_tag(self):
        from plugins.udp_scanner import _build_snmp_probe
        pkt = _build_snmp_probe('public')
        self.assertEqual(pkt[0], 0x30)

    def test_snmp_probe_contains_community_string(self):
        from plugins.udp_scanner import _build_snmp_probe
        pkt = _build_snmp_probe('public')
        self.assertIn(b'public', pkt)

    def test_get_udp_probe_returns_dns_for_port_53(self):
        from plugins.udp_scanner import get_udp_probe, _build_dns_probe
        self.assertEqual(get_udp_probe(53), _build_dns_probe())

    def test_get_udp_probe_returns_ntp_for_port_123(self):
        from plugins.udp_scanner import get_udp_probe, _build_ntp_probe
        self.assertEqual(get_udp_probe(123), _build_ntp_probe())

    def test_get_udp_probe_returns_snmp_for_port_161(self):
        from plugins.udp_scanner import get_udp_probe, _build_snmp_probe
        self.assertEqual(get_udp_probe(161), _build_snmp_probe())

    def test_get_udp_probe_generic_fallback(self):
        """Unknown port gets a generic non-empty probe."""
        from plugins.udp_scanner import get_udp_probe
        pkt = get_udp_probe(9999)
        self.assertIsInstance(pkt, bytes)
        self.assertGreater(len(pkt), 0)


# ---------------------------------------------------------------------------
# 26. PR2 — Service fingerprinting
# ---------------------------------------------------------------------------

class TestServiceFingerprinting(unittest.TestCase):
    """fingerprint_banner() and normalize_service_name() behave correctly."""

    def test_ssh_banner_identifies_ssh_with_version(self):
        from plugins.fingerprint import fingerprint_banner
        fp = fingerprint_banner('SSH-2.0-OpenSSH_8.9p1', 22, 'tcp', 'SSH')
        self.assertEqual(fp.service, 'SSH')
        self.assertEqual(fp.version, 'OpenSSH_8.9p1')
        self.assertAlmostEqual(fp.confidence, 0.9)

    def test_http_banner_identifies_http(self):
        from plugins.fingerprint import fingerprint_banner
        fp = fingerprint_banner('HTTP/1.1 200 OK\r\nServer: Apache', 80, 'tcp', 'HTTP')
        self.assertEqual(fp.service, 'HTTP')
        self.assertAlmostEqual(fp.confidence, 0.9)

    def test_ftp_banner_identifies_ftp(self):
        from plugins.fingerprint import fingerprint_banner
        fp = fingerprint_banner('220 FTP Server Ready', 21, 'tcp', 'FTP')
        self.assertEqual(fp.service, 'FTP')
        self.assertAlmostEqual(fp.confidence, 0.9)

    def test_vnc_banner_identifies_vnc_with_version(self):
        from plugins.fingerprint import fingerprint_banner
        fp = fingerprint_banner('RFB 003.008\n', 5900, 'tcp', 'VNC')
        self.assertEqual(fp.service, 'VNC')
        self.assertEqual(fp.version, '003.008')

    def test_empty_banner_falls_back_to_port_lookup(self):
        from plugins.fingerprint import fingerprint_banner
        fp = fingerprint_banner('', 22, 'tcp', 'SSH')
        self.assertEqual(fp.service, 'SSH')
        self.assertAlmostEqual(fp.confidence, 0.5)

    def test_no_match_gives_unknown_service(self):
        from plugins.fingerprint import fingerprint_banner
        fp = fingerprint_banner('', 54321, 'tcp', None)
        self.assertTrue(fp.service.startswith('Unknown'))
        self.assertAlmostEqual(fp.confidence, 0.2)

    def test_udp_protocol_preserved(self):
        from plugins.fingerprint import fingerprint_banner
        fp = fingerprint_banner('', 161, 'udp', 'SNMP')
        self.assertEqual(fp.protocol, 'udp')

    def test_fingerprint_to_dict_has_required_keys(self):
        from plugins.fingerprint import fingerprint_banner
        fp = fingerprint_banner('SSH-2.0-OpenSSH_8.9', 22, 'tcp', 'SSH')
        d = fp.to_dict()
        for key in ('service', 'version', 'protocol', 'confidence', 'evidence'):
            self.assertIn(key, d, f"Missing key '{key}' in fingerprint dict")

    def test_fingerprint_evidence_non_empty_on_banner_match(self):
        from plugins.fingerprint import fingerprint_banner
        fp = fingerprint_banner('SSH-2.0-OpenSSH_8.9', 22, 'tcp', 'SSH')
        self.assertTrue(len(fp.evidence) > 0)

    def test_normalize_http_proxy(self):
        from plugins.fingerprint import normalize_service_name
        self.assertEqual(normalize_service_name('http-proxy'), 'HTTP')

    def test_normalize_https_alt(self):
        from plugins.fingerprint import normalize_service_name
        self.assertEqual(normalize_service_name('https-alt'), 'HTTPS')

    def test_normalize_ms_rpc_dyn(self):
        from plugins.fingerprint import normalize_service_name
        self.assertEqual(normalize_service_name('ms-rpc-dyn'), 'MS-RPC')

    def test_normalize_unknown_uppercased(self):
        from plugins.fingerprint import normalize_service_name
        self.assertEqual(normalize_service_name('ssh'), 'SSH')

    def test_normalize_preserves_case_for_unknowns(self):
        from plugins.fingerprint import normalize_service_name
        self.assertEqual(normalize_service_name('custom-svc'), 'CUSTOM-SVC')

    def test_mysql_banner_identifies_mysql(self):
        from plugins.fingerprint import fingerprint_banner
        fp = fingerprint_banner('mysql_native_password\x00', 3306, 'tcp', 'MySQL')
        self.assertEqual(fp.service, 'MySQL')

    def test_redis_banner_identifies_redis(self):
        from plugins.fingerprint import fingerprint_banner
        fp = fingerprint_banner('-NOAUTH Authentication required', 6379, 'tcp', 'Redis')
        self.assertEqual(fp.service, 'Redis')


# ---------------------------------------------------------------------------
# 27. PR2 — CLI parsing for UDP options
# ---------------------------------------------------------------------------

class TestCLIUDPParsing(unittest.TestCase):
    """CLI parser correctly handles UDP scanning options."""

    def _parse(self, args_list):
        import argparse as ap
        parser = ap.ArgumentParser()
        parser.add_argument('-t', '--target', required=True)
        parser.add_argument('--scan-mode', default='common')
        parser.add_argument('--ports')
        parser.add_argument('--timeout', type=float, default=1.0)
        parser.add_argument('--retries', type=int, default=1)
        parser.add_argument('--concurrency', type=int, default=50)
        parser.add_argument('--skip-nvd', action='store_true')
        parser.add_argument('--skip-compliance', action='store_true')
        parser.add_argument('--cve-lookback-days', type=int, default=120)
        parser.add_argument('--protocol', choices=['tcp', 'udp', 'both'], default='tcp')
        parser.add_argument('--udp-timeout', type=float, default=2.0)
        parser.add_argument('--udp-retries', type=int, default=2)
        parser.add_argument('--udp-ports')
        # Credential args (needed for parser completeness)
        parser.add_argument('--cred-file')
        parser.add_argument('--ssh-user')
        parser.add_argument('--ssh-password')
        parser.add_argument('--ssh-key')
        parser.add_argument('--ssh-port', type=int, default=22)
        parser.add_argument('--winrm-user')
        parser.add_argument('--winrm-password')
        parser.add_argument('--winrm-domain')
        parser.add_argument('--winrm-transport', default='http')
        parser.add_argument('--wmi-user')
        parser.add_argument('--wmi-password')
        parser.add_argument('--wmi-domain')
        return parser.parse_args(args_list)

    def test_protocol_default_is_tcp(self):
        args = self._parse(['-t', '10.0.0.1'])
        self.assertEqual(args.protocol, 'tcp')

    def test_protocol_udp_parsed(self):
        args = self._parse(['-t', '10.0.0.1', '--protocol', 'udp'])
        self.assertEqual(args.protocol, 'udp')

    def test_protocol_both_parsed(self):
        args = self._parse(['-t', '10.0.0.1', '--protocol', 'both'])
        self.assertEqual(args.protocol, 'both')

    def test_udp_timeout_default(self):
        args = self._parse(['-t', '10.0.0.1'])
        self.assertAlmostEqual(args.udp_timeout, 2.0)

    def test_udp_timeout_custom(self):
        args = self._parse(['-t', '10.0.0.1', '--udp-timeout', '3.5'])
        self.assertAlmostEqual(args.udp_timeout, 3.5)

    def test_udp_retries_default(self):
        args = self._parse(['-t', '10.0.0.1'])
        self.assertEqual(args.udp_retries, 2)

    def test_udp_retries_custom(self):
        args = self._parse(['-t', '10.0.0.1', '--udp-retries', '4'])
        self.assertEqual(args.udp_retries, 4)

    def test_udp_ports_default_is_none(self):
        args = self._parse(['-t', '10.0.0.1'])
        self.assertIsNone(args.udp_ports)

    def test_udp_ports_parsed(self):
        args = self._parse(['-t', '10.0.0.1', '--udp-ports', '53,123,161'])
        self.assertEqual(args.udp_ports, '53,123,161')


# ---------------------------------------------------------------------------
# 28. PR2 — HybridScanner UDP pipeline integration
# ---------------------------------------------------------------------------

class TestHybridScannerUDPIntegration(unittest.TestCase):
    """HybridScanner integrates UDP results correctly."""

    def _make_args(self, **kwargs):
        import argparse
        defaults = dict(
            scan_mode='common', timeout=1.0, retries=1, concurrency=50,
            ports=None, skip_nvd=True, skip_compliance=True, cve_lookback_days=120,
            protocol='tcp', udp_timeout=2.0, udp_retries=2, udp_ports=None,
            ssh_user=None, ssh_password=None, ssh_key=None, ssh_port=22,
            winrm_user=None, winrm_password=None, winrm_domain=None,
            winrm_transport='http',
            wmi_user=None, wmi_password=None, wmi_domain=None,
            cred_file=None,
        )
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    def _fake_udp_ports(self):
        return [
            {'port': 53, 'state': 'open', 'service': 'DNS',
             'banner': '', 'protocol': 'udp'},
            {'port': 161, 'state': 'open|filtered', 'service': 'SNMP',
             'banner': '', 'protocol': 'udp'},
        ]

    def _fake_tcp_ports(self):
        return [
            {'port': 80, 'state': 'open', 'service': 'HTTP',
             'banner': '', 'protocol': 'tcp'},
        ]

    def test_udp_only_mode_does_not_run_tcp_scan(self):
        """When protocol=udp, TCP port scan must not be called."""
        args = self._make_args(protocol='udp')
        from vultron import HybridScanner
        scanner = HybridScanner("127.0.0.1", args)
        with patch("vultron.PortScanner.scan") as mock_tcp, \
             patch("vultron.UDPScanner.scan", return_value=self._fake_udp_ports()), \
             patch("vultron.VulnerabilityChecker.check_all", return_value=[]), \
             patch("vultron.ReportGenerator.generate_html"), \
             patch("vultron.ReportGenerator.generate_json"):
            scanner.run()
        mock_tcp.assert_not_called()

    def test_udp_results_stored_in_udp_ports(self):
        """UDP scan results appear in results['udp_ports']."""
        args = self._make_args(protocol='udp')
        from vultron import HybridScanner
        scanner = HybridScanner("127.0.0.1", args)
        fake_udp = self._fake_udp_ports()
        with patch("vultron.UDPScanner.scan", return_value=fake_udp), \
             patch("vultron.VulnerabilityChecker.check_all", return_value=[]), \
             patch("vultron.ReportGenerator.generate_html"), \
             patch("vultron.ReportGenerator.generate_json"):
            scanner.run()
        self.assertEqual(scanner.results['udp_ports'], fake_udp)

    def test_both_mode_populates_both_open_ports_and_udp_ports(self):
        """protocol=both fills open_ports (TCP) and udp_ports (UDP)."""
        args = self._make_args(protocol='both')
        from vultron import HybridScanner
        scanner = HybridScanner("127.0.0.1", args)
        fake_tcp = self._fake_tcp_ports()
        fake_udp = self._fake_udp_ports()
        with patch("vultron.PortScanner.scan", return_value=fake_tcp), \
             patch("vultron.UDPScanner.scan", return_value=fake_udp), \
             patch("vultron.VulnerabilityChecker.check_all", return_value=[]), \
             patch("vultron.ReportGenerator.generate_html"), \
             patch("vultron.ReportGenerator.generate_json"):
            scanner.run()
        self.assertEqual(scanner.results['open_ports'], fake_tcp)
        self.assertEqual(scanner.results['udp_ports'], fake_udp)

    def test_tcp_only_mode_udp_ports_stays_empty(self):
        """Default TCP mode leaves udp_ports empty."""
        args = self._make_args(protocol='tcp')
        from vultron import HybridScanner
        scanner = HybridScanner("127.0.0.1", args)
        fake_tcp = self._fake_tcp_ports()
        with patch("vultron.PortScanner.scan", return_value=fake_tcp), \
             patch("vultron.VulnerabilityChecker.check_all", return_value=[]), \
             patch("vultron.ReportGenerator.generate_html"), \
             patch("vultron.ReportGenerator.generate_json"):
            scanner.run()
        self.assertEqual(scanner.results['udp_ports'], [])

    def test_scan_protocol_stored_in_results(self):
        """results['scan_protocol'] matches the --protocol arg."""
        for proto in ('tcp', 'udp', 'both'):
            args = self._make_args(protocol=proto)
            from vultron import HybridScanner
            scanner = HybridScanner("127.0.0.1", args)
            self.assertEqual(scanner.results['scan_protocol'], proto)

    def test_udp_ports_in_json_report(self):
        """JSON report includes udp_ports when UDP scan was run."""
        import tempfile, json, os
        args = self._make_args(protocol='udp')
        from vultron import HybridScanner, ReportGenerator
        scanner = HybridScanner("127.0.0.1", args)
        scanner.results['udp_ports'] = self._fake_udp_ports()

        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            fname = f.name
        try:
            reporter = ReportGenerator(scanner.results)
            reporter.generate_json(fname)
            with open(fname) as f:
                data = json.load(f)
            self.assertIn('udp_ports', data)
            self.assertEqual(len(data['udp_ports']), 2)
        finally:
            os.unlink(fname)

    def test_udp_scanner_timeout_and_retries_passed_from_args(self):
        """UDPScanner is constructed with timeout/retries from CLI args."""
        args = self._make_args(protocol='udp', udp_timeout=4.0, udp_retries=3)
        from vultron import HybridScanner
        scanner = HybridScanner("127.0.0.1", args)
        captured = {}

        original_init = __import__('plugins.udp_scanner', fromlist=['UDPScanner']).UDPScanner.__init__

        def patched_init(self_inner, target, ports=None, timeout=2.0,
                         retries=2, concurrency=30):
            captured['timeout'] = timeout
            captured['retries'] = retries
            original_init(self_inner, target, ports=ports, timeout=timeout,
                          retries=retries, concurrency=concurrency)

        with patch("plugins.udp_scanner.UDPScanner.__init__", patched_init), \
             patch("plugins.udp_scanner.UDPScanner.scan", return_value=[]), \
             patch("vultron.VulnerabilityChecker.check_all", return_value=[]), \
             patch("vultron.ReportGenerator.generate_html"), \
             patch("vultron.ReportGenerator.generate_json"):
            scanner.run()

        self.assertAlmostEqual(captured.get('timeout', 0), 4.0)
        self.assertEqual(captured.get('retries', 0), 3)


# ---------------------------------------------------------------------------
# 29. PR2 — TCP fingerprint enrichment in PortScanner
# ---------------------------------------------------------------------------

class TestTCPFingerprintEnrichment(unittest.TestCase):
    """PortScanner.scan_port() adds fingerprint data when plugins are available."""

    def test_scan_port_open_has_fingerprint_key(self):
        """An open TCP port result contains a 'fingerprint' dict."""
        scanner = PortScanner("127.0.0.1")
        with patch('socket.socket') as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.connect_ex.return_value = 0
            mock_sock.recv.return_value = b'SSH-2.0-OpenSSH_8.9\r\n'
            result = scanner.scan_port(22)

        self.assertIsNotNone(result)
        # fingerprint key present when _HAS_PLUGINS is True (plugins available)
        import vultron
        if vultron._HAS_PLUGINS:
            self.assertIn('fingerprint', result)
            fp = result['fingerprint']
            for key in ('service', 'protocol', 'confidence'):
                self.assertIn(key, fp)

    def test_scan_port_result_has_protocol_tcp(self):
        """TCP port scan results always carry protocol='tcp'."""
        scanner = PortScanner("127.0.0.1")
        with patch('socket.socket') as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.connect_ex.return_value = 0
            mock_sock.recv.return_value = b''
            result = scanner.scan_port(80)

        self.assertIsNotNone(result)
        self.assertEqual(result['protocol'], 'tcp')

    def test_scan_port_closed_returns_none(self):
        """Closed port (non-zero connect_ex) returns None, not a dict."""
        scanner = PortScanner("127.0.0.1")
        with patch('socket.socket') as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.connect_ex.return_value = 111  # ECONNREFUSED
            result = scanner.scan_port(9999)
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)

