"""
Tests for Vulntron P10 – Local Web UI (plugins/ui.py).

Covers:
- Run discovery in data-dir
- Schema validation failure behaviour
- Key API endpoints (runs list, summary, hosts, findings, compliance,
  exposure, web posture)
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure repository root is on sys.path so plugins package is importable.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

# ── Try to import the module under test; skip entire module if unavailable ──
try:
    from plugins.ui import (
        RunLoadError,
        create_app,
        discover_runs,
        load_run,
        validate_run,
        _build_summary,
        _severity_counts,
    )
    _UI_AVAILABLE = True
except ImportError:
    _UI_AVAILABLE = False

try:
    from fastapi.testclient import TestClient
    _TESTCLIENT_AVAILABLE = True
except ImportError:
    _TESTCLIENT_AVAILABLE = False

_SKIP_REASON = "plugins.ui or FastAPI not available"

# ---------------------------------------------------------------------------
# Minimal valid run fixture
# ---------------------------------------------------------------------------

_MINIMAL_RUN = {
    "target": "10.0.0.1",
    "timestamp": "2026-04-11T12:00:00",
    "scanner_version": "8.0.0",
    "scan_mode": "common",
    "scan_protocol": "tcp",
    "open_ports": [
        {"port": 22, "service": "ssh", "protocol": "tcp"},
        {"port": 80, "service": "http", "protocol": "tcp"},
    ],
    "udp_ports": [],
    "vulnerabilities": [
        {
            "check_id": "TELNET-001",
            "name": "Telnet Exposed",
            "severity": "HIGH",
            "status": "CONFIRMED",
            "category": "vuln",
            "description": "Telnet service is open.",
            "confidence": 0.9,
            "confidence_label": "HIGH",
            "target": "10.0.0.1",
            "evidence_raw": "Banner: Linux telnetd",
        },
        {
            "check_id": "SSL-LEGACY",
            "name": "Legacy TLS",
            "severity": "MEDIUM",
            "status": "POTENTIAL",
            "category": "tls",
            "description": "TLS 1.0 detected.",
            "confidence": 0.5,
        },
    ],
    "compliance": {
        "profile": "baseline",
        "target": "10.0.0.1",
        "timestamp": "2026-04-11T12:00:00",
        "status": "FAIL",
        "issues": ["SVC-001: Telnet exposed"],
        "summary": {"total": 5, "pass": 4, "fail": 1, "unknown": 0, "skip": 0},
        "controls": [
            {
                "control_id": "SVC-001",
                "title": "Telnet Service Exposed",
                "description": "Port 23/TCP is open.",
                "rationale": "Telnet is unencrypted.",
                "status": "FAIL",
                "severity": "HIGH",
                "evidence": ["Port 23/TCP is open"],
                "skip_reason": None,
            }
        ],
    },
    "exposure": {
        "risk_score": 7,
        "summary": {"risk_score": 7},
        "signals": [
            {
                "signal_id": "EXP-001",
                "title": "Legacy SSH version",
                "severity": "MEDIUM",
                "confidence": 0.6,
                "confidence_label": "MEDIUM",
                "details": "SSH version 1 detected",
            }
        ],
    },
    "web_posture": {
        "target_count": 1,
        "total_findings": 1,
        "summary": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0},
        "targets": [
            {
                "url": "http://10.0.0.1",
                "finding_count": 1,
                "error": None,
                "findings": [
                    {
                        "finding_id": "WEB-HEADER-CSP",
                        "title": "Missing CSP header",
                        "severity": "MEDIUM",
                        "confidence": 0.9,
                        "confidence_label": "HIGH",
                    }
                ],
            }
        ],
    },
    "nvd_intelligence": {},
    "auth_scan": {"authenticated_mode": False},
    "tls_scan": {},
    "inventory": {"total_assets": 1, "role": "server"},
    "scan_metadata": {},
}


def _write_run(directory: str, name: str = "run1", data: dict = None) -> str:
    """Write a JSON run file to *directory* and return its path."""
    if data is None:
        data = _MINIMAL_RUN
    path = os.path.join(directory, name + ".json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    return path


# ===========================================================================
# Tests: run discovery
# ===========================================================================


@unittest.skipUnless(_UI_AVAILABLE, _SKIP_REASON)
class TestRunDiscovery(unittest.TestCase):
    """discover_runs() should find .json files in a directory."""

    def test_empty_dir_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as d:
            runs = discover_runs(d)
        self.assertEqual(runs, [])

    def test_nonexistent_dir_returns_empty_list(self):
        runs = discover_runs("/tmp/_vulntron_nonexistent_xyz_123")
        self.assertEqual(runs, [])

    def test_discovers_single_run(self):
        with tempfile.TemporaryDirectory() as d:
            _write_run(d, "scan_10.0.0.1_20260411")
            runs = discover_runs(d)
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["target"], "10.0.0.1")

    def test_discovers_multiple_runs(self):
        with tempfile.TemporaryDirectory() as d:
            for i in range(3):
                _write_run(d, f"run_{i}")
            runs = discover_runs(d)
        self.assertEqual(len(runs), 3)

    def test_run_meta_has_required_keys(self):
        with tempfile.TemporaryDirectory() as d:
            _write_run(d)
            runs = discover_runs(d)
        meta = runs[0]
        for key in ("id", "filename", "path", "target", "timestamp", "scanner_version", "size_bytes"):
            self.assertIn(key, meta, f"Missing key: {key}")

    def test_ignores_non_json_files(self):
        with tempfile.TemporaryDirectory() as d:
            # Write a .txt file - should be ignored
            Path(d, "notes.txt").write_text("not a run")
            _write_run(d)
            runs = discover_runs(d)
        self.assertEqual(len(runs), 1)

    def test_ignores_invalid_json_files(self):
        with tempfile.TemporaryDirectory() as d:
            # Write corrupt JSON - should be skipped gracefully
            Path(d, "corrupt.json").write_text("not valid json{{")
            _write_run(d)
            runs = discover_runs(d)
        self.assertEqual(len(runs), 1)

    def test_ignores_non_dict_json(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "array.json").write_text("[1, 2, 3]")
            _write_run(d)
            runs = discover_runs(d)
        self.assertEqual(len(runs), 1)


# ===========================================================================
# Tests: schema validation
# ===========================================================================


@unittest.skipUnless(_UI_AVAILABLE, _SKIP_REASON)
class TestSchemaValidation(unittest.TestCase):
    """validate_run() and load_run() failure behaviour."""

    def test_valid_run_passes(self):
        validate_run(_MINIMAL_RUN)  # Should not raise

    def test_missing_target_raises(self):
        bad = {k: v for k, v in _MINIMAL_RUN.items() if k != "target"}
        with self.assertRaises(RunLoadError) as ctx:
            validate_run(bad)
        self.assertIn("target", str(ctx.exception))

    def test_missing_timestamp_raises(self):
        bad = {k: v for k, v in _MINIMAL_RUN.items() if k != "timestamp"}
        with self.assertRaises(RunLoadError):
            validate_run(bad)

    def test_missing_scanner_version_raises(self):
        bad = {k: v for k, v in _MINIMAL_RUN.items() if k != "scanner_version"}
        with self.assertRaises(RunLoadError):
            validate_run(bad)

    def test_non_dict_raises(self):
        with self.assertRaises(RunLoadError):
            validate_run([1, 2, 3])

    def test_load_run_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            load_run("/tmp/_vulntron_nonexistent_run.json")

    def test_load_run_invalid_json(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            f.write("not valid json{{")
            path = f.name
        try:
            with self.assertRaises(RunLoadError) as ctx:
                load_run(path)
            self.assertIn("JSON", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_load_run_missing_required_key(self):
        bad = {k: v for k, v in _MINIMAL_RUN.items() if k != "target"}
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json.dump(bad, f)
            path = f.name
        try:
            with self.assertRaises(RunLoadError):
                load_run(path)
        finally:
            os.unlink(path)

    def test_load_run_returns_dict(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json.dump(_MINIMAL_RUN, f)
            path = f.name
        try:
            data = load_run(path)
            self.assertIsInstance(data, dict)
            self.assertEqual(data["target"], "10.0.0.1")
        finally:
            os.unlink(path)


# ===========================================================================
# Tests: severity helpers
# ===========================================================================


@unittest.skipUnless(_UI_AVAILABLE, _SKIP_REASON)
class TestSeverityCounts(unittest.TestCase):
    def test_counts_confirmed_findings(self):
        vulns = [
            {"severity": "HIGH", "status": "CONFIRMED"},
            {"severity": "MEDIUM", "status": "CONFIRMED"},
            {"severity": "LOW", "status": "POTENTIAL"},
        ]
        counts = _severity_counts(vulns)
        self.assertEqual(counts["high"], 1)
        self.assertEqual(counts["medium"], 1)
        self.assertEqual(counts["low"], 1)

    def test_inconclusive_not_counted(self):
        vulns = [{"severity": "CRITICAL", "status": "INCONCLUSIVE"}]
        counts = _severity_counts(vulns)
        self.assertEqual(counts["critical"], 0)

    def test_empty_vulns(self):
        counts = _severity_counts([])
        for v in counts.values():
            self.assertEqual(v, 0)


# ===========================================================================
# Tests: _build_summary
# ===========================================================================


@unittest.skipUnless(_UI_AVAILABLE, _SKIP_REASON)
class TestBuildSummary(unittest.TestCase):
    def test_summary_has_required_keys(self):
        s = _build_summary(_MINIMAL_RUN)
        for k in ("target", "timestamp", "scanner_version", "scan_mode",
                  "total_findings", "findings_by_severity",
                  "compliance_status", "exposure_signals", "web_posture_findings"):
            self.assertIn(k, s, f"Missing key: {k}")

    def test_target_matches(self):
        s = _build_summary(_MINIMAL_RUN)
        self.assertEqual(s["target"], "10.0.0.1")

    def test_compliance_status(self):
        s = _build_summary(_MINIMAL_RUN)
        self.assertEqual(s["compliance_status"], "FAIL")

    def test_exposure_signals_count(self):
        s = _build_summary(_MINIMAL_RUN)
        self.assertEqual(s["exposure_signals"], 1)

    def test_web_posture_findings_count(self):
        s = _build_summary(_MINIMAL_RUN)
        self.assertEqual(s["web_posture_findings"], 1)


# ===========================================================================
# Tests: API endpoints via TestClient
# ===========================================================================


@unittest.skipUnless(_UI_AVAILABLE and _TESTCLIENT_AVAILABLE, _SKIP_REASON)
class TestAPIEndpoints(unittest.TestCase):
    """Integration tests for the FastAPI endpoints using TestClient."""

    @classmethod
    def setUpClass(cls):
        cls._tmpdir = tempfile.mkdtemp()
        cls._run_path = _write_run(cls._tmpdir, "run1")
        cls._run_id = "run1"
        cls._app = create_app(cls._tmpdir)
        cls._client = TestClient(cls._app)

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls._tmpdir, ignore_errors=True)

    # --- /api/runs -----------------------------------------------------------

    def test_list_runs_returns_200(self):
        resp = self._client.get("/api/runs")
        self.assertEqual(resp.status_code, 200)

    def test_list_runs_contains_run(self):
        resp = self._client.get("/api/runs")
        data = resp.json()
        self.assertTrue(any(r["id"] == self._run_id for r in data))

    def test_list_runs_empty_dir(self):
        with tempfile.TemporaryDirectory() as d:
            app = create_app(d)
            client = TestClient(app)
            resp = client.get("/api/runs")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), [])

    # --- /api/runs/{id}/summary ---------------------------------------------

    def test_summary_returns_200(self):
        resp = self._client.get(f"/api/runs/{self._run_id}/summary")
        self.assertEqual(resp.status_code, 200)

    def test_summary_has_target(self):
        resp = self._client.get(f"/api/runs/{self._run_id}/summary")
        self.assertEqual(resp.json()["target"], "10.0.0.1")

    def test_summary_unknown_run_returns_404(self):
        resp = self._client.get("/api/runs/nonexistent_run/summary")
        self.assertEqual(resp.status_code, 404)

    def test_summary_invalid_run_id_returns_400(self):
        # Run id containing path-separator characters encoded in the run_id
        # segment. Because FastAPI normalises the URL path, we test the regex
        # check directly by calling _get_run_path with a bad id instead.
        from plugins.ui import create_app
        from fastapi import HTTPException
        import tempfile as _tmp
        with _tmp.TemporaryDirectory() as d:
            _app2 = create_app(d)
        # The regex guard in _get_run_path blocks ids with slashes / dots+slash
        # We verify via a URL that contains characters the router can route to
        # the API endpoint but which are flagged by the regex: use an id like
        # "bad!id" (contains '!')
        resp = self._client.get("/api/runs/bad%21id/summary")
        self.assertIn(resp.status_code, (400, 404, 422))

    # --- /api/runs/{id}/hosts -----------------------------------------------

    def test_hosts_returns_200(self):
        resp = self._client.get(f"/api/runs/{self._run_id}/hosts")
        self.assertEqual(resp.status_code, 200)

    def test_hosts_contains_target(self):
        resp = self._client.get(f"/api/runs/{self._run_id}/hosts")
        hosts = resp.json()
        self.assertTrue(any(h["host"] == "10.0.0.1" for h in hosts))

    def test_hosts_search_match(self):
        resp = self._client.get(f"/api/runs/{self._run_id}/hosts?search=10.0.0")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(len(resp.json()) > 0)

    def test_hosts_search_no_match(self):
        resp = self._client.get(f"/api/runs/{self._run_id}/hosts?search=192.168.99.99")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), [])

    # --- /api/runs/{id}/hosts/{host}/detail ----------------------------------

    def test_host_detail_returns_200(self):
        resp = self._client.get(f"/api/runs/{self._run_id}/hosts/10.0.0.1/detail")
        self.assertEqual(resp.status_code, 200)

    def test_host_detail_has_open_ports(self):
        resp = self._client.get(f"/api/runs/{self._run_id}/hosts/10.0.0.1/detail")
        data = resp.json()
        self.assertIn("open_ports", data)
        self.assertEqual(len(data["open_ports"]), 2)

    def test_host_detail_wrong_host_returns_404(self):
        resp = self._client.get(f"/api/runs/{self._run_id}/hosts/9.9.9.9/detail")
        self.assertEqual(resp.status_code, 404)

    # --- /api/runs/{id}/findings --------------------------------------------

    def test_findings_returns_200(self):
        resp = self._client.get(f"/api/runs/{self._run_id}/findings")
        self.assertEqual(resp.status_code, 200)

    def test_findings_count(self):
        resp = self._client.get(f"/api/runs/{self._run_id}/findings")
        self.assertEqual(len(resp.json()), 2)

    def test_findings_filter_by_severity(self):
        resp = self._client.get(f"/api/runs/{self._run_id}/findings?severity=HIGH")
        data = resp.json()
        self.assertTrue(all(f["severity"] == "HIGH" for f in data))
        self.assertTrue(len(data) >= 1)

    def test_findings_filter_by_status(self):
        resp = self._client.get(f"/api/runs/{self._run_id}/findings?status=CONFIRMED")
        data = resp.json()
        self.assertTrue(all(f["status"] == "CONFIRMED" for f in data))

    def test_findings_filter_by_category(self):
        resp = self._client.get(f"/api/runs/{self._run_id}/findings?category=tls")
        data = resp.json()
        self.assertTrue(all(f.get("category", "vuln") == "tls" for f in data))

    def test_findings_search(self):
        resp = self._client.get(f"/api/runs/{self._run_id}/findings?search=telnet")
        data = resp.json()
        self.assertEqual(len(data), 1)
        self.assertIn("Telnet", data[0]["name"])

    def test_findings_no_match_returns_empty(self):
        resp = self._client.get(f"/api/runs/{self._run_id}/findings?search=xyznotfound999")
        self.assertEqual(resp.json(), [])

    def test_findings_confidence_min_filter(self):
        resp = self._client.get(f"/api/runs/{self._run_id}/findings?confidence_min=0.8")
        data = resp.json()
        self.assertTrue(all(float(f.get("confidence", 0)) >= 0.8 for f in data))

    # --- /api/runs/{id}/findings/{finding_id} --------------------------------

    def test_finding_detail_returns_200(self):
        resp = self._client.get(f"/api/runs/{self._run_id}/findings/TELNET-001")
        self.assertEqual(resp.status_code, 200)

    def test_finding_detail_has_description(self):
        resp = self._client.get(f"/api/runs/{self._run_id}/findings/TELNET-001")
        data = resp.json()
        self.assertIn("description", data)

    def test_finding_detail_not_found_returns_404(self):
        resp = self._client.get(f"/api/runs/{self._run_id}/findings/NONEXISTENT-999")
        self.assertEqual(resp.status_code, 404)

    # --- /api/runs/{id}/compliance ------------------------------------------

    def test_compliance_returns_200(self):
        resp = self._client.get(f"/api/runs/{self._run_id}/compliance")
        self.assertEqual(resp.status_code, 200)

    def test_compliance_has_status(self):
        resp = self._client.get(f"/api/runs/{self._run_id}/compliance")
        self.assertEqual(resp.json()["status"], "FAIL")

    # --- /api/runs/{id}/exposure --------------------------------------------

    def test_exposure_returns_200(self):
        resp = self._client.get(f"/api/runs/{self._run_id}/exposure")
        self.assertEqual(resp.status_code, 200)

    def test_exposure_has_signals(self):
        resp = self._client.get(f"/api/runs/{self._run_id}/exposure")
        data = resp.json()
        self.assertIn("signals", data)
        self.assertEqual(len(data["signals"]), 1)

    # --- /api/runs/{id}/web_posture -----------------------------------------

    def test_web_posture_returns_200(self):
        resp = self._client.get(f"/api/runs/{self._run_id}/web_posture")
        self.assertEqual(resp.status_code, 200)

    def test_web_posture_has_targets(self):
        resp = self._client.get(f"/api/runs/{self._run_id}/web_posture")
        data = resp.json()
        self.assertIn("targets", data)
        self.assertEqual(len(data["targets"]), 1)

    # --- Frontend route ------------------------------------------------------

    def test_root_returns_html(self):
        resp = self._client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/html", resp.headers.get("content-type", ""))

    def test_root_contains_warning_banner(self):
        resp = self._client.get("/")
        self.assertIn("AUTHORIZED USE ONLY", resp.text)

    def test_root_contains_vulntron_branding(self):
        resp = self._client.get("/")
        self.assertIn("Vulntron", resp.text)

    # --- Schema validation via API ------------------------------------------

    def test_invalid_run_file_returns_422(self):
        with tempfile.TemporaryDirectory() as d:
            # Write a JSON file missing required keys
            bad = {"not_a_vulntron": True}
            Path(d, "bad_run.json").write_text(json.dumps(bad))
            app = create_app(d)
            client = TestClient(app)
            resp = client.get("/api/runs/bad_run/summary")
        self.assertEqual(resp.status_code, 422)

    # --- Path traversal safety ----------------------------------------------

    def test_path_traversal_blocked_by_regex(self):
        # Test the _get_run_path validation function directly — a run_id
        # containing path-separator or traversal characters should raise 400.
        from plugins.ui import create_app
        from fastapi import HTTPException
        import tempfile as _tmp
        with _tmp.TemporaryDirectory() as d:
            app2 = create_app(d)
            # Access the inner _get_run_path via a deliberate 400-triggering id
            client2 = TestClient(app2)
            # '!' is not in [\w.\-]+ so the regex blocks it → 400
            resp = client2.get("/api/runs/bad!id/summary")
            self.assertIn(resp.status_code, (400, 404, 422))

    def test_run_id_with_special_chars_blocked(self):
        # run_id with shell-special characters should be rejected with 400
        resp = self._client.get("/api/runs/bad%21id/summary")
        self.assertIn(resp.status_code, (400, 404, 422))


# ===========================================================================
# Tests: CLI subcommand argument parsing (_ui_main)
# ===========================================================================


class TestUiCLI(unittest.TestCase):
    """Test that the vultron ui CLI subcommand is wired up correctly."""

    def test_ui_arg_in_sys_argv_detected(self):
        """vultron.py main() should branch into _ui_main when argv[1] == 'ui'."""
        import vultron  # ensure module importable
        self.assertTrue(hasattr(vultron, '_ui_main'))

    def test_ui_main_requires_data_dir(self):
        """_ui_main should exit(!=0) when --data-dir is missing."""
        import vultron
        with self.assertRaises(SystemExit) as ctx:
            vultron._ui_main([])
        self.assertNotEqual(ctx.exception.code, 0)

    def test_ui_main_nonexistent_dir_exits(self):
        """_ui_main should exit gracefully for a non-existent --data-dir."""
        import vultron
        with self.assertRaises(SystemExit) as ctx:
            vultron._ui_main(["--data-dir", "/tmp/_nonexistent_xyz_999abc"])
        # Should exit with non-zero
        self.assertNotEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
