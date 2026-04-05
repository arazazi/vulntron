"""
Unified finding and scan-metadata schema for Vultron Phase A.

These dataclasses are the single source of truth for all scanner output.
The ``Finding`` class bridges the legacy dict-based pipeline via
``from_legacy_dict()`` / ``to_dict()`` so existing checks continue to work
without modification during the migration period.

Confidence values by status
---------------------------
CONFIRMED    → 0.9  (active probe returned definitive evidence)
POTENTIAL    → 0.5  (port/service indicates possible exposure; unverified)
INCONCLUSIVE → 0.2  (check attempted but incomplete — timeout / error)
NOT_AFFECTED → 0.0  (confirmed not vulnerable)
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Status → confidence mapping
# ---------------------------------------------------------------------------

_STATUS_CONFIDENCE: Dict[str, float] = {
    "CONFIRMED": 0.9,
    "POTENTIAL": 0.5,
    "INCONCLUSIVE": 0.2,
    "NOT_AFFECTED": 0.0,
}


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


@dataclass
class Evidence:
    """Structured evidence container for a finding.

    Attributes
    ----------
    items:
        Ordered list of human-readable evidence strings (preserved from
        the legacy ``evidence`` list).
    raw:
        Optional raw snippet (e.g. a protocol banner or hex dump).
    """

    items: List[str] = field(default_factory=list)
    raw: Optional[str] = None


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """Unified finding model — single source of truth for all scan output.

    Core fields
    -----------
    id          Stable check/finding identifier (e.g. ``MS17-010``).
    title       Short human-readable title.
    description Full description of the finding.
    status      ``CONFIRMED`` | ``POTENTIAL`` | ``INCONCLUSIVE`` | ``NOT_AFFECTED``
    severity    ``CRITICAL`` | ``HIGH`` | ``MEDIUM`` | ``LOW`` | ``INFO``
    confidence  Float 0.0–1.0 derived from status (see module docstring).
    target      Host/IP that was scanned.
    port        TCP/UDP port number, or ``None`` if not port-specific.
    service     Service name (e.g. ``SMB``, ``HTTP``), or ``None``.
    evidence    Structured :class:`Evidence` container.
    cve_refs    List of CVE identifiers (e.g. ``["CVE-2017-0144"]``).
    cvss        CVSS base score, or ``None``.
    remediation Recommended remediation text, or ``None``.
    cisa_kev    Whether this finding appears in the CISA KEV catalogue.
    exploit_available  Whether a public exploit is known to exist.
    name        Legacy display name alias (preserved for backward compat).
    scan_timestamp  ISO-8601 timestamp of when the check ran, or ``None``.
    """

    id: str
    title: str
    description: str
    status: str        # CONFIRMED | POTENTIAL | INCONCLUSIVE | NOT_AFFECTED
    severity: str      # CRITICAL | HIGH | MEDIUM | LOW | INFO
    confidence: float  # 0.0 – 1.0
    target: str
    port: Optional[int] = None
    service: Optional[str] = None
    evidence: Evidence = field(default_factory=Evidence)
    cve_refs: List[str] = field(default_factory=list)
    cvss: Optional[float] = None
    remediation: Optional[str] = None
    cisa_kev: bool = False
    exploit_available: bool = False
    name: Optional[str] = None          # legacy alias
    scan_timestamp: Optional[str] = None

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Return a dict compatible with the legacy finding format.

        All original keys are preserved so existing code (reporters,
        counter helpers, existing tests) continues to work without change.
        New fields (``confidence``, ``cve_refs``, ``evidence_raw``,
        ``target``, ``scan_timestamp``) are added alongside the legacy keys.
        """
        first_cve = self.cve_refs[0] if self.cve_refs else "N/A"
        return {
            # Legacy keys — unchanged
            "id": self.id,
            "cve": first_cve,
            "name": self.name or self.title,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "port": self.port,
            "affected_service": self.service,
            "description": self.description,
            "evidence": list(self.evidence.items),
            "cisa_kev": self.cisa_kev,
            "exploit_available": self.exploit_available,
            "cvss": self.cvss,
            "remediation": self.remediation,
            # New unified fields
            "confidence": self.confidence,
            "cve_refs": list(self.cve_refs),
            "evidence_raw": self.evidence.raw,
            "target": self.target,
            "scan_timestamp": self.scan_timestamp,
        }

    # ------------------------------------------------------------------
    # Adapter / factory
    # ------------------------------------------------------------------

    @classmethod
    def from_legacy_dict(cls, d: Dict[str, Any], target: str = "") -> "Finding":
        """Adapt a legacy finding dict to a unified :class:`Finding` object.

        This is the primary adapter used during the migration period so that
        existing :class:`VulnerabilityChecker` findings can flow through the
        unified pipeline without any changes to the check implementations.
        """
        status = d.get("status", "INCONCLUSIVE")
        cve = d.get("cve", "N/A")
        cve_refs: List[str] = [cve] if cve and cve != "N/A" else []

        ev_raw = d.get("evidence", [])
        if isinstance(ev_raw, list):
            evidence = Evidence(items=[str(e) for e in ev_raw])
        else:
            evidence = Evidence()

        return cls(
            id=d.get("id", ""),
            title=d.get("title", d.get("name", "")),
            description=d.get("description", ""),
            status=status,
            severity=d.get("severity", "MEDIUM"),
            confidence=_STATUS_CONFIDENCE.get(status, 0.2),
            target=target or d.get("target", ""),
            port=d.get("port"),
            service=d.get("affected_service", d.get("service")),
            evidence=evidence,
            cve_refs=cve_refs,
            cvss=d.get("cvss"),
            remediation=d.get("remediation"),
            cisa_kev=bool(d.get("cisa_kev", False)),
            exploit_available=bool(d.get("exploit_available", False)),
            name=d.get("name"),
            scan_timestamp=d.get("scan_timestamp"),
        )


# ---------------------------------------------------------------------------
# ScanMetadata
# ---------------------------------------------------------------------------


@dataclass
class ScanMetadata:
    """Scan-level metadata emitted alongside findings.

    Attributes
    ----------
    scan_id     Unique scan identifier (UUID4 string).
    target      Host/IP that was scanned.
    started     ISO-8601 timestamp when the scan began.
    ended       ISO-8601 timestamp when the scan finished, or ``None``.
    config      Dict of scan configuration (timeout, retries, concurrency, mode).
    """

    scan_id: str
    target: str
    started: str
    ended: Optional[str] = None
    config: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dict suitable for JSON output."""
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "started": self.started,
            "ended": self.ended,
            "config": dict(self.config),
        }

    @staticmethod
    def new(target: str, config: Optional[Dict[str, Any]] = None) -> "ScanMetadata":
        """Create a new :class:`ScanMetadata` with a fresh UUID and current timestamp."""
        return ScanMetadata(
            scan_id=str(uuid.uuid4()),
            target=target,
            started=datetime.now(timezone.utc).isoformat(),
            config=config or {},
        )
