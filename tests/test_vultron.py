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


if __name__ == "__main__":
    unittest.main(verbosity=2)

