"""
Vulntron P10 – Local Nessus-like Web UI
========================================
FastAPI backend that serves a read-only dashboard for browsing Vulntron JSON
scan outputs.

Launch via::

    python vultron.py ui --data-dir ./runs
    python -m vulntron_ui --data-dir ./runs   # standalone entry point

Binds to 127.0.0.1:8000 by default (local-only).
All data is read-only; no scanning or exploitation is performed.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Optional FastAPI / uvicorn import with graceful fallback
# ---------------------------------------------------------------------------
try:
    from fastapi import FastAPI, HTTPException, Query
    from fastapi.responses import HTMLResponse, JSONResponse
    _HAS_FASTAPI = True
except ImportError:  # pragma: no cover
    _HAS_FASTAPI = False

try:
    from plugins.secrets import deep_redact_dict
    _HAS_REDACT = True
except ImportError:
    try:
        from secrets import deep_redact_dict  # type: ignore[no-redef]
        _HAS_REDACT = True
    except ImportError:
        _HAS_REDACT = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Recognised top-level keys for Vulntron JSON schema validation
_REQUIRED_KEYS = {"target", "timestamp", "scanner_version"}
_KNOWN_KEYS = {
    "target", "timestamp", "scanner_version", "scan_mode", "scan_protocol",
    "cve_lookback_days", "open_ports", "udp_ports", "vulnerabilities",
    "nvd_intelligence", "compliance", "exposure", "auth_scan", "tls_scan",
    "inventory", "web_posture", "scan_metadata",
}

# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------


class RunLoadError(ValueError):
    """Raised when a run file fails validation."""


def _safe_redact(data: Any) -> Any:
    """Redact sensitive values from *data* if the secrets module is available."""
    if _HAS_REDACT:
        return deep_redact_dict(data)
    return data


def discover_runs(data_dir: str) -> List[Dict[str, Any]]:
    """Return a list of run metadata dicts discovered under *data_dir*.

    Each dict contains: ``id``, ``filename``, ``path``, ``target``,
    ``timestamp``, ``scanner_version``, and ``size_bytes``.

    Files are sorted newest-first by timestamp embedded in the filename (or
    mtime as fallback).

    Parameters
    ----------
    data_dir:
        Directory to search for ``*.json`` files.

    Returns
    -------
    list[dict]
        Sorted list of run metadata (may be empty).
    """
    base = Path(data_dir).expanduser().resolve()
    if not base.is_dir():
        return []

    runs: List[Dict[str, Any]] = []
    for fpath in sorted(base.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        meta = _load_run_meta(fpath)
        if meta is not None:
            runs.append(meta)
    return runs


def _load_run_meta(fpath: Path) -> Optional[Dict[str, Any]]:
    """Load minimal metadata from a run file without full validation."""
    try:
        with fpath.open(encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return None
        ts = data.get("timestamp", "")
        return {
            "id": fpath.stem,
            "filename": fpath.name,
            "path": str(fpath),
            "target": data.get("target", "unknown"),
            "timestamp": ts,
            "scanner_version": data.get("scanner_version", "unknown"),
            "size_bytes": fpath.stat().st_size,
        }
    except Exception:
        return None


def validate_run(data: Any) -> None:
    """Validate that *data* looks like a Vulntron JSON report.

    Raises
    ------
    RunLoadError
        If *data* is not a dict or is missing required keys.
    """
    if not isinstance(data, dict):
        raise RunLoadError("Run data must be a JSON object (dict), got: " + type(data).__name__)
    missing = _REQUIRED_KEYS - data.keys()
    if missing:
        raise RunLoadError(
            f"Run is missing required key(s): {', '.join(sorted(missing))}. "
            f"Ensure this file was produced by Vulntron."
        )


def load_run(path: str) -> Dict[str, Any]:
    """Load, validate and return a single run from *path*.

    Raises
    ------
    RunLoadError
        On parse or validation failure.
    FileNotFoundError
        If the file does not exist.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Run file not found: {path}")
    try:
        with p.open(encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise RunLoadError(f"Failed to parse JSON from {path}: {exc}") from exc
    validate_run(data)
    return data


def _severity_counts(vulns: List[Dict]) -> Dict[str, int]:
    """Return confirmed severity counts from *vulns*."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    for v in vulns:
        status = str(v.get("status", "")).upper()
        if status not in ("CONFIRMED", "POTENTIAL"):
            continue
        sev = str(v.get("severity", "")).upper()
        key = sev.lower() if sev.lower() in counts else "unknown"
        counts[key] += 1
    return counts


def _build_summary(data: Dict[str, Any]) -> Dict[str, Any]:
    """Build a dashboard summary dict from a full run."""
    vulns = data.get("vulnerabilities") or []
    sev_counts = _severity_counts(vulns)

    compliance = data.get("compliance") or {}
    comp_status = compliance.get("status", "N/A") if isinstance(compliance, dict) else "N/A"
    comp_summary = compliance.get("summary", {}) if isinstance(compliance, dict) else {}

    exposure = data.get("exposure") or {}
    exp_count = len(exposure.get("signals", [])) if isinstance(exposure, dict) else 0

    web_posture = data.get("web_posture") or {}
    web_findings = web_posture.get("total_findings", 0) if isinstance(web_posture, dict) else 0

    inventory = data.get("inventory") or {}
    total_assets = inventory.get("total_assets", 1) if isinstance(inventory, dict) else 1

    open_ports = data.get("open_ports") or []
    udp_ports = data.get("udp_ports") or []

    return {
        "target": data.get("target", "unknown"),
        "timestamp": data.get("timestamp", ""),
        "scanner_version": data.get("scanner_version", "unknown"),
        "scan_mode": data.get("scan_mode", "common"),
        "total_assets": total_assets,
        "open_tcp_ports": len(open_ports),
        "open_udp_ports": len(udp_ports),
        "findings_by_severity": sev_counts,
        "total_findings": len(vulns),
        "compliance_status": comp_status,
        "compliance_summary": comp_summary,
        "exposure_signals": exp_count,
        "web_posture_findings": web_findings,
    }


# ---------------------------------------------------------------------------
# FastAPI application factory
# ---------------------------------------------------------------------------


def create_app(data_dir: str) -> "FastAPI":
    """Create and configure the FastAPI application.

    Parameters
    ----------
    data_dir:
        Directory to search for Vulntron JSON run files.

    Returns
    -------
    FastAPI
        Configured application instance.
    """
    if not _HAS_FASTAPI:
        raise ImportError(
            "FastAPI is required for the Vulntron UI.  "
            "Install it with: pip install 'fastapi[standard]' uvicorn"
        )

    app = FastAPI(
        title="Vulntron UI",
        description="Read-only local dashboard for Vulntron scan results",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url=None,
    )

    _data_dir = str(Path(data_dir).expanduser().resolve())

    # -----------------------------------------------------------------------
    # Helper to look up a run by id
    # -----------------------------------------------------------------------

    def _get_run_path(run_id: str) -> Path:
        """Return a validated, resolved :class:`~pathlib.Path` for *run_id*.

        Sanitises *run_id* defensively:

        1. Strips any path components with :func:`os.path.basename`.
        2. Rejects IDs that are not purely alphanumeric / dash / underscore /
           single dots (i.e., rejects ``..``, absolute paths, etc.).
        3. Resolves the candidate path and checks it is contained within
           *_data_dir* using :meth:`~pathlib.Path.relative_to`.
        4. Verifies the file exists.

        Raises 400 on sanitisation / traversal failure, 404 if not found.
        """
        # 1. Strip any path-separator components
        safe_id = os.path.basename(run_id)
        # 2. Allow only safe characters; reject ".." and leading dot
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_.\-]*$', safe_id) or '..' in safe_id:
            raise HTTPException(status_code=400, detail="Invalid run_id")
        # 3. Resolve and check containment
        candidate = (Path(_data_dir) / (safe_id + ".json")).resolve()
        try:
            candidate.relative_to(Path(_data_dir).resolve())
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid run_id (path traversal)")
        # 4. Existence check
        if not candidate.is_file():
            raise HTTPException(status_code=404, detail=f"Run not found: {run_id}")
        return candidate

    def _load_or_404(run_id: str) -> Dict[str, Any]:
        """Load and validate a run by *run_id*.

        Uses the pre-validated :class:`~pathlib.Path` from :func:`_get_run_path`
        to open the file, so no user-provided string reaches a file system call.
        """
        safe_path: Path = _get_run_path(run_id)
        try:
            with safe_path.open(encoding="utf-8") as fh:
                data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=422,
                detail=f"Failed to parse JSON from run file: {exc}",
            ) from exc
        try:
            validate_run(data)
        except RunLoadError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return data

    # -----------------------------------------------------------------------
    # API routes
    # -----------------------------------------------------------------------

    @app.get("/api/runs", response_class=JSONResponse, tags=["runs"])
    def list_runs():
        """List all available scan runs in the data directory."""
        return discover_runs(_data_dir)

    @app.get("/api/runs/{run_id}/summary", response_class=JSONResponse, tags=["runs"])
    def get_run_summary(run_id: str):
        """Return a dashboard summary for a specific run."""
        data = _load_or_404(run_id)
        return _build_summary(data)

    @app.get("/api/runs/{run_id}/hosts", response_class=JSONResponse, tags=["hosts"])
    def get_hosts(
        run_id: str,
        search: Optional[str] = Query(None, description="Filter hosts by name/IP substring"),
    ):
        """Return host list with per-host summary badges."""
        data = _load_or_404(run_id)
        target = data.get("target", "unknown")
        open_ports = data.get("open_ports") or []
        udp_ports = data.get("udp_ports") or []
        vulns = data.get("vulnerabilities") or []
        compliance = data.get("compliance") or {}
        inventory = data.get("inventory") or {}

        host = {
            "host": target,
            "open_tcp_ports": len(open_ports),
            "open_udp_ports": len(udp_ports),
            "severity_counts": _severity_counts(vulns),
            "compliance_status": (
                compliance.get("status", "N/A") if isinstance(compliance, dict) else "N/A"
            ),
            "inventory_role": (
                inventory.get("role", "unknown") if isinstance(inventory, dict) else "unknown"
            ),
        }

        if search and search.lower() not in target.lower():
            return []
        return [host]

    @app.get("/api/runs/{run_id}/hosts/{host}/detail", response_class=JSONResponse, tags=["hosts"])
    def get_host_detail(run_id: str, host: str):
        """Return full detail for a host: ports, vulns, compliance, exposure, web posture."""
        data = _load_or_404(run_id)
        # Validate host matches target
        if host != data.get("target", ""):
            raise HTTPException(status_code=404, detail=f"Host not found: {host}")

        redacted = _safe_redact(data)
        return {
            "host": host,
            "open_ports": redacted.get("open_ports") or [],
            "udp_ports": redacted.get("udp_ports") or [],
            "tls_scan": redacted.get("tls_scan") or {},
            "vulnerabilities": redacted.get("vulnerabilities") or [],
            "compliance": redacted.get("compliance") or {},
            "exposure": redacted.get("exposure") or {},
            "web_posture": redacted.get("web_posture") or {},
            "inventory": redacted.get("inventory") or {},
        }

    @app.get("/api/runs/{run_id}/findings", response_class=JSONResponse, tags=["findings"])
    def get_findings(
        run_id: str,
        severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)"),
        status: Optional[str] = Query(None, description="Filter by status (CONFIRMED/POTENTIAL/INCONCLUSIVE)"),
        category: Optional[str] = Query(None, description="Filter by category (vuln/tls/compliance/exposure/web)"),
        search: Optional[str] = Query(None, description="Search within finding title/description"),
        confidence_min: Optional[float] = Query(None, ge=0.0, le=1.0, description="Minimum confidence score"),
    ):
        """Return all findings for a run with optional filters."""
        data = _load_or_404(run_id)
        redacted = _safe_redact(data)
        vulns = redacted.get("vulnerabilities") or []

        results = []
        for v in vulns:
            if severity and str(v.get("severity", "")).upper() != severity.upper():
                continue
            if status and str(v.get("status", "")).upper() != status.upper():
                continue
            cat = str(v.get("category", "vuln")).lower()
            if category and cat != category.lower():
                continue
            if confidence_min is not None:
                conf = v.get("confidence", 0.0)
                if conf is None or float(conf) < confidence_min:
                    continue
            if search:
                sl = search.lower()
                title = str(v.get("name", v.get("check_id", ""))).lower()
                desc = str(v.get("description", "")).lower()
                if sl not in title and sl not in desc:
                    continue
            results.append(v)

        return results

    @app.get("/api/runs/{run_id}/findings/{finding_id}", response_class=JSONResponse, tags=["findings"])
    def get_finding_detail(run_id: str, finding_id: str):
        """Return detail for a specific finding by check_id / finding_id."""
        data = _load_or_404(run_id)
        redacted = _safe_redact(data)
        vulns = redacted.get("vulnerabilities") or []

        for v in vulns:
            fid = str(v.get("check_id", v.get("finding_id", v.get("name", ""))))
            if fid == finding_id:
                return v
        raise HTTPException(status_code=404, detail=f"Finding not found: {finding_id}")

    @app.get("/api/runs/{run_id}/compliance", response_class=JSONResponse, tags=["compliance"])
    def get_compliance(run_id: str):
        """Return compliance report for a run."""
        data = _load_or_404(run_id)
        return _safe_redact(data.get("compliance") or {})

    @app.get("/api/runs/{run_id}/exposure", response_class=JSONResponse, tags=["exposure"])
    def get_exposure(run_id: str):
        """Return exposure signals for a run."""
        data = _load_or_404(run_id)
        return _safe_redact(data.get("exposure") or {})

    @app.get("/api/runs/{run_id}/web_posture", response_class=JSONResponse, tags=["web"])
    def get_web_posture(run_id: str):
        """Return web posture findings for a run."""
        data = _load_or_404(run_id)
        return _safe_redact(data.get("web_posture") or {})

    # -----------------------------------------------------------------------
    # Frontend — single-page HTML app
    # -----------------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    @app.get("/{path:path}", response_class=HTMLResponse)
    def serve_ui(path: str = ""):
        """Serve the single-page HTML/JS frontend."""
        return HTMLResponse(content=_HTML_APP, status_code=200)

    return app


# ---------------------------------------------------------------------------
# Embedded single-page HTML application
# ---------------------------------------------------------------------------

_HTML_APP = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Vulntron UI – Scan Results Dashboard</title>
<style>
:root {
  --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
  --border: #30363d; --text: #c9d1d9; --text2: #8b949e;
  --accent: #58a6ff; --accent2: #1f6feb;
  --crit: #f85149; --high: #ff7b72; --med: #e3b341; --low: #3fb950; --info: #8b949e;
  --pass: #3fb950; --fail: #f85149; --warn: #e3b341;
  --red: rgba(248,81,73,.15); --yellow: rgba(227,179,65,.15); --green: rgba(63,185,80,.15);
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,sans-serif;
  background:var(--bg);color:var(--text);line-height:1.5}
/* Warning banner */
#warn{background:#5a1e1e;color:#ffa0a0;padding:8px 20px;font-size:12px;
  text-align:center;border-bottom:1px solid #7a2e2e}
/* Layout */
#layout{display:flex;height:calc(100vh - 40px)}
#sidebar{width:240px;min-width:200px;background:var(--bg2);border-right:1px solid var(--border);
  display:flex;flex-direction:column;overflow-y:auto}
#main{flex:1;overflow-y:auto;padding:0}
/* Sidebar */
.sidebar-header{padding:16px;border-bottom:1px solid var(--border);font-size:18px;
  font-weight:700;color:var(--accent)}
.sidebar-section{padding:8px 0}
.sidebar-label{padding:4px 16px;font-size:11px;text-transform:uppercase;
  letter-spacing:.08em;color:var(--text2)}
.sidebar-item{padding:8px 16px;cursor:pointer;font-size:13px;
  transition:background .15s;border-left:2px solid transparent}
.sidebar-item:hover{background:var(--bg3)}
.sidebar-item.active{background:var(--bg3);border-left-color:var(--accent);color:var(--accent)}
.run-select{margin:10px 12px;background:var(--bg3);border:1px solid var(--border);
  color:var(--text);padding:6px 10px;border-radius:6px;font-size:12px;width:calc(100% - 24px)}
/* Page sections */
.page{display:none;padding:24px}
.page.active{display:block}
h1{font-size:22px;font-weight:700;margin-bottom:4px}
.subtitle{color:var(--text2);font-size:13px;margin-bottom:20px}
/* Cards */
.cards{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:24px}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;
  padding:16px;flex:1;min-width:160px}
.card-title{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--text2);margin-bottom:8px}
.card-value{font-size:28px;font-weight:700}
.card-value.crit{color:var(--crit)} .card-value.high{color:var(--high)}
.card-value.med{color:var(--med)} .card-value.low{color:var(--low)}
.card-value.pass{color:var(--pass)} .card-value.fail{color:var(--fail)}
/* Severity badges */
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600}
.badge-CRITICAL,.badge-critical{background:var(--red);color:var(--crit)}
.badge-HIGH,.badge-high{background:rgba(255,123,114,.15);color:var(--high)}
.badge-MEDIUM,.badge-medium{background:var(--yellow);color:var(--med)}
.badge-LOW,.badge-low{background:var(--green);color:var(--low)}
.badge-INFO,.badge-info{background:rgba(139,148,158,.15);color:var(--info)}
.badge-CONFIRMED{background:rgba(63,185,80,.15);color:var(--pass)}
.badge-POTENTIAL{background:rgba(227,179,65,.15);color:var(--med)}
.badge-INCONCLUSIVE{background:rgba(139,148,158,.15);color:var(--info)}
.badge-PASS{background:var(--green);color:var(--pass)}
.badge-FAIL{background:var(--red);color:var(--fail)}
.badge-WARN{background:var(--yellow);color:var(--warn)}
/* Tables */
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:var(--bg3);color:var(--text2);padding:8px 12px;text-align:left;
  font-size:11px;text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid var(--border)}
td{padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:top}
tr:hover td{background:rgba(255,255,255,.02)}
tr.clickable{cursor:pointer}
/* Sections */
.section{background:var(--bg2);border:1px solid var(--border);border-radius:8px;
  margin-bottom:20px;overflow:hidden}
.section-header{padding:14px 20px;border-bottom:1px solid var(--border);display:flex;
  align-items:center;justify-content:space-between;cursor:pointer}
.section-title{font-size:14px;font-weight:600}
.section-body{padding:20px}
.section-body.collapsed{display:none}
/* Search/filter bar */
.filter-bar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
.filter-bar input,.filter-bar select{background:var(--bg2);border:1px solid var(--border);
  color:var(--text);padding:6px 10px;border-radius:6px;font-size:13px}
.filter-bar input{flex:1;min-width:160px}
/* Finding detail */
.detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
.detail-item label{font-size:11px;text-transform:uppercase;letter-spacing:.06em;
  color:var(--text2);display:block;margin-bottom:4px}
.detail-item .val{font-size:14px}
pre.evidence{background:var(--bg3);border:1px solid var(--border);border-radius:6px;
  padding:12px;font-size:12px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}
/* Port table */
.port-chip{display:inline-block;background:var(--bg3);border:1px solid var(--border);
  border-radius:4px;padding:2px 8px;font-size:12px;font-family:monospace;margin:2px}
/* Breadcrumb */
.breadcrumb{font-size:13px;color:var(--text2);margin-bottom:16px}
.breadcrumb a{color:var(--accent);cursor:pointer;text-decoration:none}
.breadcrumb a:hover{text-decoration:underline}
/* Empty / loading */
.empty{text-align:center;padding:48px;color:var(--text2);font-size:14px}
.loading{text-align:center;padding:48px;color:var(--text2)}
/* Severity bar */
.sev-bar{display:flex;height:8px;border-radius:4px;overflow:hidden;margin-top:4px;min-width:80px}
.sev-seg{height:100%}
/* Tabs */
.tabs{display:flex;border-bottom:1px solid var(--border);margin-bottom:16px;gap:0}
.tab{padding:8px 16px;cursor:pointer;font-size:13px;border-bottom:2px solid transparent;
  color:var(--text2)}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab-panel{display:none} .tab-panel.active{display:block}
/* Compliance */
.ctrl-item{background:var(--bg3);border:1px solid var(--border);border-radius:6px;
  padding:12px;margin-bottom:8px}
.ctrl-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:4px}
.ctrl-id{font-family:monospace;font-size:12px;color:var(--accent)}
.ctrl-title{font-weight:600;font-size:13px}
.ctrl-body{font-size:12px;color:var(--text2)}
/* Responsive */
@media(max-width:700px){
  #sidebar{display:none}
  #layout{height:auto;flex-direction:column}
}
</style>
</head>
<body>
<div id="warn">⚠️ AUTHORIZED USE ONLY – This dashboard may contain sensitive security data. Ensure you are authorized to view these reports.</div>
<div id="layout">
  <aside id="sidebar">
    <div class="sidebar-header">🛡️ Vulntron UI</div>
    <div style="padding:10px 12px;border-bottom:1px solid var(--border)">
      <select id="runSelect" class="run-select" onchange="onRunChange(this.value)">
        <option value="">— select a run —</option>
      </select>
    </div>
    <div class="sidebar-section">
      <div class="sidebar-label">Views</div>
      <div class="sidebar-item active" onclick="nav('dashboard')" id="nav-dashboard">📊 Dashboard</div>
      <div class="sidebar-item" onclick="nav('hosts')" id="nav-hosts">🖥️ Hosts</div>
      <div class="sidebar-item" onclick="nav('findings')" id="nav-findings">🔍 Findings</div>
      <div class="sidebar-item" onclick="nav('compliance')" id="nav-compliance">✅ Compliance</div>
      <div class="sidebar-item" onclick="nav('exposure')" id="nav-exposure">📡 Exposure</div>
      <div class="sidebar-item" onclick="nav('web')" id="nav-web">🌐 Web Posture</div>
    </div>
    <div style="padding:16px;font-size:11px;color:var(--text2);margin-top:auto;border-top:1px solid var(--border)">
      Read-only • Local only<br>Vulntron UI v1.0
    </div>
  </aside>
  <main id="main">

    <!-- Dashboard -->
    <div class="page active" id="page-dashboard">
      <div style="padding:24px">
        <h1>Dashboard</h1>
        <div class="subtitle" id="dash-subtitle">Select a run to view scan results</div>
        <div id="dash-no-run" class="empty">No run selected. Use the dropdown on the left to choose a scan run.</div>
        <div id="dash-content" style="display:none">
          <div class="cards" id="dash-cards"></div>
          <div class="section">
            <div class="section-header" onclick="toggleSection(this)">
              <span class="section-title">Findings by Severity</span><span>▼</span>
            </div>
            <div class="section-body">
              <table><thead><tr><th>Severity</th><th>Count</th><th>Bar</th></tr></thead>
              <tbody id="sev-table"></tbody></table>
            </div>
          </div>
          <div class="section">
            <div class="section-header" onclick="toggleSection(this)">
              <span class="section-title">Scan Information</span><span>▼</span>
            </div>
            <div class="section-body" id="dash-scan-info"></div>
          </div>
        </div>
      </div>
    </div>

    <!-- Hosts -->
    <div class="page" id="page-hosts">
      <div style="padding:24px">
        <h1>Hosts</h1>
        <div class="subtitle">Discovered hosts and their security posture</div>
        <div class="filter-bar">
          <input type="text" id="host-search" placeholder="Search by host/IP…" oninput="filterHosts()"/>
        </div>
        <div id="hosts-content"><div class="empty">Select a run to view hosts.</div></div>
      </div>
    </div>

    <!-- Host Detail (hidden page) -->
    <div class="page" id="page-host-detail">
      <div style="padding:24px">
        <div class="breadcrumb"><a onclick="nav('hosts')">Hosts</a> / <span id="hd-hostname"></span></div>
        <h1 id="hd-title"></h1>
        <div class="subtitle" id="hd-subtitle"></div>
        <div class="tabs">
          <div class="tab active" onclick="switchTab(this,'hd-ports')">Ports &amp; Services</div>
          <div class="tab" onclick="switchTab(this,'hd-vulns')">Vulnerabilities</div>
          <div class="tab" onclick="switchTab(this,'hd-compliance')">Compliance</div>
          <div class="tab" onclick="switchTab(this,'hd-exposure')">Exposure</div>
          <div class="tab" onclick="switchTab(this,'hd-web')">Web Posture</div>
        </div>
        <div class="tab-panel active" id="hd-ports"><div class="loading">Loading…</div></div>
        <div class="tab-panel" id="hd-vulns"><div class="loading">Loading…</div></div>
        <div class="tab-panel" id="hd-compliance"><div class="loading">Loading…</div></div>
        <div class="tab-panel" id="hd-exposure"><div class="loading">Loading…</div></div>
        <div class="tab-panel" id="hd-web"><div class="loading">Loading…</div></div>
      </div>
    </div>

    <!-- Findings -->
    <div class="page" id="page-findings">
      <div style="padding:24px">
        <h1>Findings</h1>
        <div class="subtitle">All vulnerabilities and security findings</div>
        <div class="filter-bar">
          <input type="text" id="find-search" placeholder="Search findings…" oninput="applyFindingFilters()"/>
          <select id="find-sev" onchange="applyFindingFilters()">
            <option value="">All Severities</option>
            <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option>
            <option>LOW</option><option>INFO</option>
          </select>
          <select id="find-status" onchange="applyFindingFilters()">
            <option value="">All Statuses</option>
            <option>CONFIRMED</option><option>POTENTIAL</option><option>INCONCLUSIVE</option>
          </select>
          <select id="find-cat" onchange="applyFindingFilters()">
            <option value="">All Categories</option>
            <option value="vuln">Vulnerability</option>
            <option value="tls">TLS</option>
            <option value="compliance">Compliance</option>
            <option value="exposure">Exposure</option>
            <option value="web">Web</option>
          </select>
        </div>
        <div id="findings-content"><div class="empty">Select a run to view findings.</div></div>
      </div>
    </div>

    <!-- Finding Detail (hidden page) -->
    <div class="page" id="page-finding-detail">
      <div style="padding:24px">
        <div class="breadcrumb"><a onclick="nav('findings')">Findings</a> / <span id="fd-id"></span></div>
        <h1 id="fd-title"></h1>
        <div class="subtitle" id="fd-subtitle"></div>
        <div class="detail-grid" id="fd-meta"></div>
        <div class="section">
          <div class="section-header"><span class="section-title">Description</span></div>
          <div class="section-body" id="fd-desc"></div>
        </div>
        <div class="section" id="fd-evidence-section">
          <div class="section-header" onclick="toggleSection(this)">
            <span class="section-title">Evidence (redacted)</span><span>▼</span>
          </div>
          <div class="section-body" id="fd-evidence"></div>
        </div>
        <div class="section" id="fd-cve-section" style="display:none">
          <div class="section-header"><span class="section-title">CVE References</span></div>
          <div class="section-body" id="fd-cves"></div>
        </div>
      </div>
    </div>

    <!-- Compliance -->
    <div class="page" id="page-compliance">
      <div style="padding:24px">
        <h1>Compliance</h1>
        <div class="subtitle">Baseline compliance control results</div>
        <div id="compliance-content"><div class="empty">Select a run to view compliance results.</div></div>
      </div>
    </div>

    <!-- Exposure -->
    <div class="page" id="page-exposure">
      <div style="padding:24px">
        <h1>Exposure &amp; Patch Risk</h1>
        <div class="subtitle">Heuristic exposure signals and patch risk indicators</div>
        <div id="exposure-content"><div class="empty">Select a run to view exposure signals.</div></div>
      </div>
    </div>

    <!-- Web Posture -->
    <div class="page" id="page-web">
      <div style="padding:24px">
        <h1>Web Application Posture</h1>
        <div class="subtitle">Safe web posture check results</div>
        <div id="web-content"><div class="empty">Select a run to view web posture results.</div></div>
      </div>
    </div>

  </main>
</div>

<script>
'use strict';
// ── State ────────────────────────────────────────────────────────────────────
let currentRun = null;
let allFindings = [];
let currentPage = 'dashboard';

// ── Navigation ───────────────────────────────────────────────────────────────
function nav(page) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.sidebar-item').forEach(i => i.classList.remove('active'));
  const el = document.getElementById('page-' + page);
  if (el) el.classList.add('active');
  const nav = document.getElementById('nav-' + page);
  if (nav) nav.classList.add('active');
  currentPage = page;
  if (currentRun) loadPageData(page);
}

function switchTab(tabEl, panelId) {
  const parent = tabEl.closest('.page, #page-host-detail');
  parent.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  parent.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  tabEl.classList.add('active');
  document.getElementById(panelId).classList.add('active');
}

function toggleSection(header) {
  const body = header.nextElementSibling;
  body.classList.toggle('collapsed');
  header.querySelector('span:last-child').textContent = body.classList.contains('collapsed') ? '▶' : '▼';
}

// ── Run selection ─────────────────────────────────────────────────────────────
async function loadRuns() {
  const sel = document.getElementById('runSelect');
  try {
    const runs = await apiFetch('/api/runs');
    sel.innerHTML = '<option value="">— select a run —</option>';
    runs.forEach(r => {
      const opt = document.createElement('option');
      opt.value = r.id;
      const ts = r.timestamp ? r.timestamp.replace('T',' ').substring(0,19) : '';
      opt.textContent = `${r.target}  ${ts}`;
      sel.appendChild(opt);
    });
    if (runs.length === 1) {
      sel.value = runs[0].id;
      onRunChange(runs[0].id);
    }
  } catch(e) {
    sel.innerHTML = '<option value="">Error loading runs</option>';
  }
}

async function onRunChange(runId) {
  currentRun = runId || null;
  if (!currentRun) return;
  loadPageData(currentPage);
}

async function loadPageData(page) {
  if (!currentRun) return;
  const loaders = {
    dashboard: loadDashboard,
    hosts: loadHosts,
    findings: loadFindings,
    compliance: loadCompliance,
    exposure: loadExposure,
    web: loadWeb,
  };
  if (loaders[page]) await loaders[page]();
}

// ── API helpers ───────────────────────────────────────────────────────────────
async function apiFetch(url) {
  const r = await fetch(url);
  if (!r.ok) {
    const j = await r.json().catch(() => ({detail: r.statusText}));
    throw new Error(j.detail || r.statusText);
  }
  return r.json();
}

function esc(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function badge(val, type) {
  const cls = type || val;
  return `<span class="badge badge-${esc(cls)}">${esc(val)}</span>`;
}

function severityColor(sev) {
  const m = {CRITICAL:'var(--crit)',HIGH:'var(--high)',MEDIUM:'var(--med)',LOW:'var(--low)',INFO:'var(--info)'};
  return m[String(sev).toUpperCase()] || 'var(--text2)';
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
async function loadDashboard() {
  try {
    const s = await apiFetch(`/api/runs/${currentRun}/summary`);
    document.getElementById('dash-no-run').style.display = 'none';
    document.getElementById('dash-content').style.display = 'block';
    const ts = (s.timestamp||'').replace('T',' ').substring(0,19);
    document.getElementById('dash-subtitle').textContent = `Target: ${s.target}  •  Scanned: ${ts}  •  Version: ${s.scanner_version}`;
    const sev = s.findings_by_severity || {};
    const cards = [
      {title:'Total Findings', value: s.total_findings||0, cls:''},
      {title:'Critical', value: sev.critical||0, cls:'crit'},
      {title:'High', value: sev.high||0, cls:'high'},
      {title:'Medium', value: sev.medium||0, cls:'med'},
      {title:'Low', value: sev.low||0, cls:'low'},
      {title:'Compliance', value: s.compliance_status||'N/A', cls: s.compliance_status==='PASS'?'pass':s.compliance_status==='FAIL'?'fail':''},
      {title:'Exposure Signals', value: s.exposure_signals||0, cls:''},
      {title:'Web Findings', value: s.web_posture_findings||0, cls:''},
      {title:'Open TCP Ports', value: s.open_tcp_ports||0, cls:''},
    ];
    document.getElementById('dash-cards').innerHTML = cards.map(c =>
      `<div class="card"><div class="card-title">${esc(c.title)}</div>
       <div class="card-value ${c.cls}">${esc(String(c.value))}</div></div>`
    ).join('');
    const sevOrder = ['critical','high','medium','low','info','unknown'];
    const total = Object.values(sev).reduce((a,b)=>a+b,0)||1;
    document.getElementById('sev-table').innerHTML = sevOrder.map(k => {
      const cnt = sev[k]||0;
      const pct = Math.round(cnt/total*100);
      return `<tr><td>${badge(k.toUpperCase())}</td><td>${cnt}</td>
        <td><div style="background:var(--bg3);border-radius:4px;height:8px;width:100%;min-width:80px">
          <div style="width:${pct}%;height:8px;background:${severityColor(k)};border-radius:4px"></div>
        </div></td></tr>`;
    }).join('');
    document.getElementById('dash-scan-info').innerHTML =
      `<table><tbody>
        <tr><td style="color:var(--text2);width:160px">Target</td><td>${esc(s.target)}</td></tr>
        <tr><td style="color:var(--text2)">Timestamp</td><td>${esc(s.timestamp)}</td></tr>
        <tr><td style="color:var(--text2)">Scanner Version</td><td>${esc(s.scanner_version)}</td></tr>
        <tr><td style="color:var(--text2)">Scan Mode</td><td>${esc(s.scan_mode)}</td></tr>
        <tr><td style="color:var(--text2)">Open TCP Ports</td><td>${s.open_tcp_ports||0}</td></tr>
        <tr><td style="color:var(--text2)">Open UDP Ports</td><td>${s.open_udp_ports||0}</td></tr>
        <tr><td style="color:var(--text2)">Total Assets</td><td>${s.total_assets||1}</td></tr>
      </tbody></table>`;
  } catch(e) {
    document.getElementById('dash-content').innerHTML = `<div class="empty">Error: ${esc(e.message)}</div>`;
  }
}

// ── Hosts ─────────────────────────────────────────────────────────────────────
let hostsData = [];
async function loadHosts() {
  const cont = document.getElementById('hosts-content');
  cont.innerHTML = '<div class="loading">Loading…</div>';
  try {
    hostsData = await apiFetch(`/api/runs/${currentRun}/hosts`);
    renderHosts(hostsData);
  } catch(e) {
    cont.innerHTML = `<div class="empty">Error: ${esc(e.message)}</div>`;
  }
}

function renderHosts(hosts) {
  const cont = document.getElementById('hosts-content');
  if (!hosts.length) { cont.innerHTML = '<div class="empty">No hosts found.</div>'; return; }
  cont.innerHTML = `<table>
    <thead><tr><th>Host</th><th>TCP Ports</th><th>UDP Ports</th><th>Severity Counts</th><th>Compliance</th><th>Role</th></tr></thead>
    <tbody>${hosts.map(h => {
      const sc = h.severity_counts||{};
      const sevHtml = ['critical','high','medium','low'].map(k =>
        sc[k] ? `<span class="badge badge-${k.toUpperCase()}" title="${k}">${sc[k]}</span> ` : ''
      ).join('');
      return `<tr class="clickable" onclick="openHostDetail('${esc(h.host)}')">
        <td style="font-family:monospace;color:var(--accent)">${esc(h.host)}</td>
        <td>${h.open_tcp_ports||0}</td>
        <td>${h.open_udp_ports||0}</td>
        <td>${sevHtml||'<span style="color:var(--text2)">none</span>'}</td>
        <td>${badge(h.compliance_status||'N/A')}</td>
        <td style="color:var(--text2)">${esc(h.inventory_role||'')}</td>
      </tr>`;
    }).join('')}</tbody></table>`;
}

function filterHosts() {
  const q = document.getElementById('host-search').value.trim().toLowerCase();
  renderHosts(q ? hostsData.filter(h => h.host.toLowerCase().includes(q)) : hostsData);
}

// ── Host Detail ───────────────────────────────────────────────────────────────
async function openHostDetail(host) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.sidebar-item').forEach(i => i.classList.remove('active'));
  document.getElementById('page-host-detail').classList.add('active');
  document.getElementById('hd-hostname').textContent = host;
  document.getElementById('hd-title').textContent = host;
  document.getElementById('hd-subtitle').textContent = 'Host detail view';
  ['hd-ports','hd-vulns','hd-compliance','hd-exposure','hd-web'].forEach(id =>
    document.getElementById(id).innerHTML = '<div class="loading">Loading…</div>');
  // Reset tabs
  document.querySelectorAll('#page-host-detail .tab').forEach((t,i) => t.classList.toggle('active',i===0));
  document.querySelectorAll('#page-host-detail .tab-panel').forEach((p,i) => p.classList.toggle('active',i===0));
  try {
    const d = await apiFetch(`/api/runs/${currentRun}/hosts/${encodeURIComponent(host)}/detail`);
    renderHostPorts(d);
    renderHostVulns(d);
    renderHostCompliance(d);
    renderHostExposure(d);
    renderHostWeb(d);
    document.getElementById('hd-subtitle').textContent =
      `${(d.open_ports||[]).length} TCP • ${(d.open_udp_ports||[]).length} UDP ports`;
  } catch(e) {
    document.getElementById('hd-ports').innerHTML = `<div class="empty">Error: ${esc(e.message)}</div>`;
  }
}

function renderHostPorts(d) {
  const ports = d.open_ports||[];
  const udp = d.udp_ports||[];
  let html = '';
  if (ports.length) {
    html += '<h3 style="margin-bottom:8px;font-size:14px">TCP Ports</h3>';
    html += `<table><thead><tr><th>Port</th><th>Service</th><th>Version</th><th>TLS</th></tr></thead><tbody>`;
    const tls = d.tls_scan||{};
    ports.forEach(p => {
      const pKey = String(p.port);
      const tlsInfo = tls[pKey] || {};
      const hasTls = tlsInfo.tls_version || tlsInfo.cert_cn;
      html += `<tr>
        <td><span class="port-chip">${esc(p.port)}/tcp</span></td>
        <td>${esc(p.service||'')}</td>
        <td style="font-size:12px;color:var(--text2)">${esc(p.version||p.banner||'')}</td>
        <td>${hasTls ? badge('TLS') : ''}</td>
      </tr>`;
    });
    html += '</tbody></table>';
  }
  if (udp.length) {
    html += '<h3 style="margin:16px 0 8px;font-size:14px">UDP Ports</h3>';
    html += `<table><thead><tr><th>Port</th><th>Service</th><th>State</th></tr></thead><tbody>`;
    udp.forEach(p => {
      html += `<tr>
        <td><span class="port-chip">${esc(p.port)}/udp</span></td>
        <td>${esc(p.service||'')}</td>
        <td style="color:var(--text2)">${esc(p.state||'')}</td>
      </tr>`;
    });
    html += '</tbody></table>';
  }
  if (!ports.length && !udp.length) html = '<div class="empty">No open ports found.</div>';
  document.getElementById('hd-ports').innerHTML = html;
}

function renderHostVulns(d) {
  const vulns = d.vulnerabilities||[];
  if (!vulns.length) { document.getElementById('hd-vulns').innerHTML = '<div class="empty">No findings.</div>'; return; }
  document.getElementById('hd-vulns').innerHTML = renderFindingsTable(vulns);
}

function renderHostCompliance(d) {
  const c = d.compliance||{};
  const ctrl = c.controls||[];
  if (!ctrl.length && !c.status) {
    document.getElementById('hd-compliance').innerHTML = '<div class="empty">No compliance data.</div>'; return;
  }
  let html = `<div class="cards">
    <div class="card"><div class="card-title">Status</div>
      <div class="card-value ${c.status==='PASS'?'pass':'fail'}">${esc(c.status||'N/A')}</div></div>
    <div class="card"><div class="card-title">Pass</div><div class="card-value pass">${c.summary?.pass||0}</div></div>
    <div class="card"><div class="card-title">Fail</div><div class="card-value fail">${c.summary?.fail||0}</div></div>
    <div class="card"><div class="card-title">Unknown</div><div class="card-value">${c.summary?.unknown||0}</div></div>
  </div>`;
  ctrl.forEach(ct => {
    html += `<div class="ctrl-item">
      <div class="ctrl-head">
        <span><span class="ctrl-id">${esc(ct.control_id)}</span>
          <span style="margin-left:8px;font-weight:600">${esc(ct.title||'')}</span></span>
        ${badge(ct.status||'UNKNOWN')}
      </div>
      <div class="ctrl-body">${esc(ct.description||'')}
        ${ct.evidence&&ct.evidence.length ? '<br><em>Evidence: ' + ct.evidence.map(esc).join('; ') + '</em>' : ''}
      </div>
    </div>`;
  });
  document.getElementById('hd-compliance').innerHTML = html;
}

function renderHostExposure(d) {
  const exp = d.exposure||{};
  const sigs = exp.signals||[];
  if (!sigs.length) { document.getElementById('hd-exposure').innerHTML = '<div class="empty">No exposure signals.</div>'; return; }
  document.getElementById('hd-exposure').innerHTML = renderSignalsTable(sigs);
}

function renderHostWeb(d) {
  const wp = d.web_posture||{};
  if (!wp.targets||!wp.targets.length) {
    document.getElementById('hd-web').innerHTML = '<div class="empty">No web posture data.</div>'; return;
  }
  document.getElementById('hd-web').innerHTML = renderWebPosture(wp);
}

// ── Findings ──────────────────────────────────────────────────────────────────
async function loadFindings() {
  const cont = document.getElementById('findings-content');
  cont.innerHTML = '<div class="loading">Loading…</div>';
  try {
    allFindings = await apiFetch(`/api/runs/${currentRun}/findings`);
    applyFindingFilters();
  } catch(e) {
    cont.innerHTML = `<div class="empty">Error: ${esc(e.message)}</div>`;
  }
}

function applyFindingFilters() {
  const q = document.getElementById('find-search').value.trim().toLowerCase();
  const sev = document.getElementById('find-sev').value.toUpperCase();
  const st = document.getElementById('find-status').value.toUpperCase();
  const cat = document.getElementById('find-cat').value.toLowerCase();
  let filtered = allFindings;
  if (sev) filtered = filtered.filter(f => String(f.severity||'').toUpperCase() === sev);
  if (st) filtered = filtered.filter(f => String(f.status||'').toUpperCase() === st);
  if (cat) filtered = filtered.filter(f => String(f.category||'vuln').toLowerCase() === cat);
  if (q) filtered = filtered.filter(f => {
    const title = String(f.name||f.check_id||'').toLowerCase();
    const desc = String(f.description||'').toLowerCase();
    return title.includes(q) || desc.includes(q);
  });
  document.getElementById('findings-content').innerHTML = filtered.length
    ? renderFindingsTable(filtered, true)
    : '<div class="empty">No findings match the current filters.</div>';
}

function renderFindingsTable(findings, clickable=false) {
  return `<table>
    <thead><tr><th>ID / Name</th><th>Severity</th><th>Status</th><th>Category</th><th>Target</th></tr></thead>
    <tbody>${findings.map(f => {
      const fid = f.check_id||f.finding_id||f.name||'—';
      const row = `<tr ${clickable?'class="clickable" onclick="openFindingDetail(\''+esc(fid)+'\')"':''}>
        <td style="font-family:monospace;font-size:12px">${esc(fid)}</td>
        <td>${badge(f.severity||'INFO')}</td>
        <td>${badge(f.status||'INCONCLUSIVE')}</td>
        <td style="color:var(--text2)">${esc(f.category||'vuln')}</td>
        <td style="font-size:12px;color:var(--text2)">${esc(f.target||f.host||'')}</td>
      </tr>`;
      return row;
    }).join('')}</tbody></table>`;
}

// ── Finding Detail ────────────────────────────────────────────────────────────
async function openFindingDetail(findingId) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.sidebar-item').forEach(i => i.classList.remove('active'));
  document.getElementById('page-finding-detail').classList.add('active');
  try {
    const f = await apiFetch(`/api/runs/${currentRun}/findings/${encodeURIComponent(findingId)}`);
    document.getElementById('fd-id').textContent = findingId;
    document.getElementById('fd-title').textContent = f.name||f.check_id||findingId;
    document.getElementById('fd-subtitle').textContent = f.title||'';
    document.getElementById('fd-meta').innerHTML = [
      {label:'Severity', val: badge(f.severity||'INFO')},
      {label:'Status', val: badge(f.status||'INCONCLUSIVE')},
      {label:'Category', val: esc(f.category||'vuln')},
      {label:'Confidence', val: esc(String(f.confidence_label||'') + (f.confidence!=null?' ('+f.confidence+')':''))},
      {label:'Target / Host', val: esc(f.target||f.host||'')},
      {label:'Port / Service', val: esc(f.port ? f.port+'/'+f.protocol : f.service||'')},
    ].map(i => `<div class="detail-item"><label>${i.label}</label><div class="val">${i.val}</div></div>`).join('');
    document.getElementById('fd-desc').textContent = f.description||'No description available.';
    const evid = f.evidence_raw||f.evidence||f.details||'';
    const evidStr = Array.isArray(evid) ? evid.join('\n') : String(evid);
    document.getElementById('fd-evidence').innerHTML = evidStr
      ? `<pre class="evidence">${esc(evidStr)}</pre>` : '<div style="color:var(--text2)">No evidence available.</div>';
    const cves = f.cve_refs||f.cves||[];
    if (cves.length) {
      document.getElementById('fd-cve-section').style.display='';
      document.getElementById('fd-cves').innerHTML = cves.map(c =>
        `<a href="https://nvd.nist.gov/vuln/detail/${esc(c)}" target="_blank" rel="noopener noreferrer"
           style="color:var(--accent);text-decoration:none;margin-right:8px">${esc(c)}</a>`
      ).join('');
    } else {
      document.getElementById('fd-cve-section').style.display='none';
    }
  } catch(e) {
    document.getElementById('fd-title').textContent = 'Error';
    document.getElementById('fd-desc').textContent = e.message;
  }
}

// ── Compliance ────────────────────────────────────────────────────────────────
async function loadCompliance() {
  const cont = document.getElementById('compliance-content');
  cont.innerHTML = '<div class="loading">Loading…</div>';
  try {
    const c = await apiFetch(`/api/runs/${currentRun}/compliance`);
    if (!c||!Object.keys(c).length) { cont.innerHTML = '<div class="empty">No compliance data for this run.</div>'; return; }
    let html = `<div class="cards">
      <div class="card"><div class="card-title">Status</div>
        <div class="card-value ${c.status==='PASS'?'pass':'fail'}">${esc(c.status||'N/A')}</div></div>
      <div class="card"><div class="card-title">Profile</div><div class="card-value" style="font-size:18px">${esc(c.profile||'baseline')}</div></div>
      <div class="card"><div class="card-title">Pass</div><div class="card-value pass">${c.summary?.pass||0}</div></div>
      <div class="card"><div class="card-title">Fail</div><div class="card-value fail">${c.summary?.fail||0}</div></div>
      <div class="card"><div class="card-title">Unknown</div><div class="card-value">${c.summary?.unknown||0}</div></div>
      <div class="card"><div class="card-title">Total Controls</div><div class="card-value">${c.summary?.total||0}</div></div>
    </div>`;
    const ctrl = c.controls||[];
    if (ctrl.length) {
      html += '<div class="section"><div class="section-header" onclick="toggleSection(this)"><span class="section-title">Controls</span><span>▼</span></div><div class="section-body">';
      ctrl.forEach(ct => {
        const sc = ct.status||'UNKNOWN';
        html += `<div class="ctrl-item">
          <div class="ctrl-head">
            <span><span class="ctrl-id">${esc(ct.control_id)}</span>
              <span style="margin-left:8px;font-weight:600;font-size:13px">${esc(ct.title||'')}</span></span>
            ${badge(sc)}
          </div>
          <div class="ctrl-body">${esc(ct.description||'')}
            ${ct.rationale ? '<br><em style="color:var(--text2)">'+esc(ct.rationale)+'</em>' : ''}
            ${ct.evidence&&ct.evidence.length ? '<br><strong>Evidence:</strong> '+ct.evidence.map(esc).join('; ') : ''}
          </div>
        </div>`;
      });
      html += '</div></div>';
    }
    cont.innerHTML = html;
  } catch(e) {
    cont.innerHTML = `<div class="empty">Error: ${esc(e.message)}</div>`;
  }
}

// ── Exposure ──────────────────────────────────────────────────────────────────
function renderSignalsTable(signals) {
  if (!signals.length) return '<div class="empty">No signals.</div>';
  return `<table>
    <thead><tr><th>Signal ID</th><th>Title</th><th>Severity</th><th>Confidence</th><th>Details</th></tr></thead>
    <tbody>${signals.map(s => `<tr>
      <td style="font-family:monospace;font-size:12px">${esc(s.signal_id||s.id||'')}</td>
      <td>${esc(s.title||s.name||'')}</td>
      <td>${badge(s.severity||'INFO')}</td>
      <td style="color:var(--text2)">${esc(s.confidence_label||String(s.confidence||''))}</td>
      <td style="font-size:12px;color:var(--text2)">${esc(s.details||s.description||'')}</td>
    </tr>`).join('')}</tbody></table>`;
}

async function loadExposure() {
  const cont = document.getElementById('exposure-content');
  cont.innerHTML = '<div class="loading">Loading…</div>';
  try {
    const exp = await apiFetch(`/api/runs/${currentRun}/exposure`);
    if (!exp||!Object.keys(exp).length) { cont.innerHTML = '<div class="empty">No exposure data for this run.</div>'; return; }
    const sigs = exp.signals||[];
    const summ = exp.summary||{};
    let html = `<div class="cards">
      <div class="card"><div class="card-title">Total Signals</div><div class="card-value">${sigs.length}</div></div>
      <div class="card"><div class="card-title">Risk Score</div><div class="card-value">${esc(String(exp.risk_score||summ.risk_score||'N/A'))}</div></div>
    </div>`;
    html += renderSignalsTable(sigs);
    cont.innerHTML = html;
  } catch(e) {
    cont.innerHTML = `<div class="empty">Error: ${esc(e.message)}</div>`;
  }
}

// ── Web Posture ────────────────────────────────────────────────────────────────
function renderWebPosture(wp) {
  const targets = wp.targets||[];
  if (!targets.length) return '<div class="empty">No web targets scanned.</div>';
  let html = `<div class="cards">
    <div class="card"><div class="card-title">Targets</div><div class="card-value">${wp.target_count||targets.length}</div></div>
    <div class="card"><div class="card-title">Total Findings</div><div class="card-value">${wp.total_findings||0}</div></div>
  </div>`;
  targets.forEach(t => {
    html += `<div class="section">
      <div class="section-header" onclick="toggleSection(this)">
        <span class="section-title" style="font-family:monospace">${esc(t.url||t.target||'')}</span>
        <span>▼</span>
      </div>
      <div class="section-body">`;
    const findings = t.findings||[];
    if (t.error) html += `<div style="color:var(--fail)">Error: ${esc(t.error)}</div>`;
    if (findings.length) {
      html += `<table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Confidence</th></tr></thead><tbody>`;
      findings.forEach(f => {
        html += `<tr>
          <td style="font-family:monospace;font-size:12px">${esc(f.finding_id||f.check_id||'')}</td>
          <td>${esc(f.title||f.name||'')}</td>
          <td>${badge(f.severity||'INFO')}</td>
          <td style="color:var(--text2)">${esc(f.confidence_label||String(f.confidence||''))}</td>
        </tr>`;
      });
      html += '</tbody></table>';
    } else if (!t.error) {
      html += '<div style="color:var(--pass)">No findings for this target.</div>';
    }
    html += '</div></div>';
  });
  return html;
}

async function loadWeb() {
  const cont = document.getElementById('web-content');
  cont.innerHTML = '<div class="loading">Loading…</div>';
  try {
    const wp = await apiFetch(`/api/runs/${currentRun}/web_posture`);
    if (!wp||!Object.keys(wp).length) { cont.innerHTML = '<div class="empty">No web posture data for this run.</div>'; return; }
    cont.innerHTML = renderWebPosture(wp);
  } catch(e) {
    cont.innerHTML = `<div class="empty">Error: ${esc(e.message)}</div>`;
  }
}

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', loadRuns);
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# CLI entry point helper
# ---------------------------------------------------------------------------


def run_server(
    data_dir: str,
    host: str = "127.0.0.1",
    port: int = 8000,
    open_browser: bool = False,
) -> None:
    """Start the Vulntron UI server.

    Parameters
    ----------
    data_dir:
        Directory containing Vulntron JSON run files.
    host:
        Bind address (default ``127.0.0.1``).
    port:
        TCP port (default ``8000``).
    open_browser:
        If ``True``, open the default browser after startup.
    """
    if not _HAS_FASTAPI:
        print(
            "[ERROR] FastAPI is required for the Vulntron UI.\n"
            "Install it with:  pip install 'fastapi[standard]' uvicorn"
        )
        raise SystemExit(1)

    try:
        import uvicorn
    except ImportError:
        print(
            "[ERROR] uvicorn is required to run the Vulntron UI.\n"
            "Install it with:  pip install uvicorn"
        )
        raise SystemExit(1)

    data_path = Path(data_dir).expanduser().resolve()
    if not data_path.is_dir():
        print(f"[ERROR] --data-dir does not exist or is not a directory: {data_dir}")
        raise SystemExit(1)

    app = create_app(str(data_path))

    url = f"http://{host}:{port}"
    print(f"\n{'='*70}")
    print("  Vulntron UI  –  Read-only scan results dashboard")
    print(f"  URL   : {url}")
    print(f"  Data  : {data_path}")
    print(f"  NOTE  : Authorized use only. Reports may contain sensitive data.")
    print(f"{'='*70}\n")

    if open_browser:
        import threading
        import webbrowser

        def _open():
            import time
            time.sleep(1.2)
            webbrowser.open(url)

        threading.Thread(target=_open, daemon=True).start()

    uvicorn.run(app, host=host, port=port, log_level="info")
