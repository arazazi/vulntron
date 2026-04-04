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


if __name__ == '__main__':
    unittest.main(verbosity=2)
