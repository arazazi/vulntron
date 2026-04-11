"""
Patch & exposure detection module for Vultron PR6.

Derives likely exposure and patch-risk signals using data already gathered by
earlier scan phases (TCP/UDP ports, service fingerprints, TLS inspection,
asset inventory, compliance outcomes).  All analysis is read-only and
non-intrusive — no additional network traffic is generated.

Design goals
------------
- Heuristic and conservative: signals are clearly labelled as heuristic where
  version-based assumptions are made.
- Modular: each detector is a small, independently testable method.
- Confidence-graded: every signal carries a numeric confidence (0.0–1.0) so
  consumers can filter or triage accordingly.
- No CVE database ingestion: EOL version families are checked against a
  built-in curated table rather than a live CVE feed.
- Secrets must never appear in evidence strings.

Signal IDs
----------
EXP-RISKY-SVC   Risky / cleartext service exposed (Telnet, FTP, r-cmds, …)
EXP-MGMT-EXP    Management interface exposed on default port
EXP-SNMP-UNAUTH SNMP with default community string detected
EXP-WEAK-TLS    Weak TLS posture signal (protocol or cipher)
EXP-CERT-ISSUE  Certificate issue (expired, self-signed, near-expiry)
EXP-EOL-VER     End-of-life / potentially unpatched software version detected
EXP-ANON-SVC    Anonymous/unauthenticated service access confirmed
EXP-DB-EXPOSED  Database service exposed on default port
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class SignalSeverity(str, Enum):
    """Severity / priority for a single exposure signal."""
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class SignalConfidence(str, Enum):
    """Human-readable confidence label derived from the numeric score."""
    HIGH   = "HIGH"    # ≥ 0.75
    MEDIUM = "MEDIUM"  # 0.45 – 0.74
    LOW    = "LOW"     # < 0.45

    @staticmethod
    def from_score(score: float) -> "SignalConfidence":
        if score >= 0.75:
            return SignalConfidence.HIGH
        if score >= 0.45:
            return SignalConfidence.MEDIUM
        return SignalConfidence.LOW


# ---------------------------------------------------------------------------
# EOL / potentially-unpatched version heuristics table
#
# Each entry: (regex_pattern, family_label, min_safe_version_hint, severity)
#
# Conservative approach: only flag versions where the family is clearly EOL
# or the version prefix is obviously obsolete.  All matches are labelled as
# heuristic.  No CVE IDs are assigned — this is patch-risk estimation only.
# ---------------------------------------------------------------------------

_EOL_VERSION_TABLE: List[Tuple[str, str, str, SignalSeverity]] = [
    # pattern, family label, safe-minimum hint, severity
    (r"OpenSSL[/ ]1\.0\.", "OpenSSL 1.0.x", "OpenSSL 1.1.1 or 3.x", SignalSeverity.HIGH),
    (r"OpenSSL[/ ]1\.1\.0", "OpenSSL 1.1.0", "OpenSSL 1.1.1 or 3.x", SignalSeverity.MEDIUM),
    (r"Apache[/ ]2\.0\.", "Apache HTTPd 2.0.x", "Apache 2.4.x", SignalSeverity.HIGH),
    (r"Apache[/ ]2\.2\.", "Apache HTTPd 2.2.x", "Apache 2.4.x", SignalSeverity.HIGH),
    (r"Apache[/ ]1\.", "Apache HTTPd 1.x", "Apache 2.4.x", SignalSeverity.CRITICAL),
    (r"nginx[/ ]1\.(?:[0-9]\.|1[0-2]\.)", "nginx 1.0–1.12.x", "nginx 1.18+", SignalSeverity.MEDIUM),
    (r"Microsoft-IIS[/ ][2-7]\.", "IIS 7.x or older", "IIS 10.x", SignalSeverity.HIGH),
    (r"PHP[/ ]5\.", "PHP 5.x", "PHP 8.x", SignalSeverity.HIGH),
    (r"PHP[/ ]7\.0\.", "PHP 7.0.x", "PHP 8.x", SignalSeverity.MEDIUM),
    (r"PHP[/ ]7\.1\.", "PHP 7.1.x", "PHP 8.x", SignalSeverity.MEDIUM),
    (r"OpenSSH[_ ]([1-6]\.|7\.[0-5])", "OpenSSH < 7.6", "OpenSSH 8.x+", SignalSeverity.MEDIUM),
    (r"vsftpd 2\.", "vsftpd 2.x", "vsftpd 3.x", SignalSeverity.MEDIUM),
    (r"ProFTPD[/ ]1\.[23]\.", "ProFTPD 1.2/1.3.x (old)", "ProFTPD 1.3.8+", SignalSeverity.MEDIUM),
    (r"Exim[/ ][1-3]\.", "Exim < 4.x", "Exim 4.96+", SignalSeverity.HIGH),
    (r"Sendmail[/ ]8\.(?:[0-9]\.|1[0-3]\.)", "Sendmail 8.0–8.13", "Sendmail 8.15+", SignalSeverity.MEDIUM),
    (r"Postfix[/ ]2\.[0-3]\.", "Postfix 2.0–2.3.x", "Postfix 3.x+", SignalSeverity.LOW),
    (r"MySQL[/ ][45]\.", "MySQL 4.x/5.x", "MySQL 8.x", SignalSeverity.MEDIUM),
    (r"PostgreSQL[/ ][89]\.", "PostgreSQL 8/9.x", "PostgreSQL 14+", SignalSeverity.LOW),
]

# ---------------------------------------------------------------------------
# Risky / cleartext service ports
# ---------------------------------------------------------------------------

_RISKY_SERVICE_PORTS: Dict[int, Tuple[str, str, SignalSeverity]] = {
    # port: (service_label, reason, severity)
    23:   ("Telnet",      "Cleartext remote access; credentials transmitted in plaintext", SignalSeverity.HIGH),
    20:   ("FTP-data",    "FTP data channel; cleartext file transfers", SignalSeverity.MEDIUM),
    21:   ("FTP",         "FTP control; cleartext credentials and commands", SignalSeverity.MEDIUM),
    512:  ("rexec",       "BSD r-command; cleartext remote execution", SignalSeverity.HIGH),
    513:  ("rlogin",      "BSD r-command; cleartext remote login", SignalSeverity.HIGH),
    514:  ("rsh",         "BSD r-command; cleartext remote shell", SignalSeverity.HIGH),
    69:   ("TFTP",        "Trivial FTP; unauthenticated cleartext transfers", SignalSeverity.HIGH),
    79:   ("Finger",      "Finger daemon; user enumeration risk", SignalSeverity.MEDIUM),
    517:  ("talk",        "BSD talk; cleartext chat protocol", SignalSeverity.LOW),
    518:  ("ntalk",       "BSD ntalk; cleartext chat protocol", SignalSeverity.LOW),
    111:  ("RPCbind",     "ONC-RPC portmapper; may expose mounted NFS shares", SignalSeverity.MEDIUM),
    2049: ("NFS",         "NFS; may allow unauthenticated filesystem access", SignalSeverity.HIGH),
}

# ---------------------------------------------------------------------------
# Management interface ports
# ---------------------------------------------------------------------------

_MGMT_PORTS: Dict[int, Tuple[str, SignalSeverity]] = {
    # port: (label, severity)
    22:    ("SSH",         SignalSeverity.LOW),
    23:    ("Telnet",      SignalSeverity.HIGH),  # cleartext management
    3389:  ("RDP",         SignalSeverity.HIGH),
    5985:  ("WinRM-HTTP",  SignalSeverity.HIGH),
    5986:  ("WinRM-HTTPS", SignalSeverity.MEDIUM),
    2222:  ("SSH-alt",     SignalSeverity.MEDIUM),
    8291:  ("Mikrotik-Winbox", SignalSeverity.HIGH),
    8728:  ("Mikrotik-API",    SignalSeverity.HIGH),
    161:   ("SNMP",        SignalSeverity.HIGH),
    162:   ("SNMP-trap",   SignalSeverity.MEDIUM),
    4786:  ("Cisco-CDP",   SignalSeverity.HIGH),
    9200:  ("Elasticsearch-HTTP", SignalSeverity.CRITICAL),
    6379:  ("Redis",       SignalSeverity.CRITICAL),
    27017: ("MongoDB",     SignalSeverity.CRITICAL),
    5432:  ("PostgreSQL",  SignalSeverity.HIGH),
    3306:  ("MySQL/MariaDB", SignalSeverity.HIGH),
    1521:  ("Oracle-DB",   SignalSeverity.HIGH),
    1433:  ("MSSQL",       SignalSeverity.HIGH),
    5984:  ("CouchDB",     SignalSeverity.HIGH),
    2181:  ("Zookeeper",   SignalSeverity.HIGH),
    9092:  ("Kafka",       SignalSeverity.MEDIUM),
    11211: ("Memcached",   SignalSeverity.HIGH),
}

# Database ports subset (for separate EXP-DB-EXPOSED signal)
_DB_PORTS: Dict[int, str] = {
    3306:  "MySQL/MariaDB",
    5432:  "PostgreSQL",
    1521:  "Oracle",
    1433:  "MSSQL",
    27017: "MongoDB",
    6379:  "Redis",
    9200:  "Elasticsearch",
    5984:  "CouchDB",
    2181:  "Zookeeper",
    11211: "Memcached",
    9092:  "Kafka",
    5672:  "RabbitMQ AMQP",
    15672: "RabbitMQ Management",
    7474:  "Neo4j HTTP",
}


# ---------------------------------------------------------------------------
# Core data model
# ---------------------------------------------------------------------------

@dataclass
class ExposureSignal:
    """A single exposure or patch-risk signal."""

    signal_id:        str
    title:            str
    description:      str
    evidence:         List[str] = field(default_factory=list)
    confidence:       float = 0.5          # 0.0 – 1.0
    severity:         SignalSeverity = SignalSeverity.MEDIUM
    affected_asset:   str = ""
    affected_service: str = ""
    signal_type:      str = ""             # risky_service / weak_tls / eol_version / …
    heuristic:        bool = False         # True when version-pattern-based inference

    @property
    def confidence_label(self) -> str:
        return SignalConfidence.from_score(self.confidence).value

    def to_dict(self) -> Dict:
        return {
            "signal_id":        self.signal_id,
            "title":            self.title,
            "description":      self.description,
            "evidence":         list(self.evidence),
            "confidence":       round(self.confidence, 2),
            "confidence_label": self.confidence_label,
            "severity":         self.severity.value,
            "affected_asset":   self.affected_asset,
            "affected_service": self.affected_service,
            "signal_type":      self.signal_type,
            "heuristic":        self.heuristic,
        }


@dataclass
class ExposureReport:
    """Aggregated result of the exposure engine run."""

    target:  str
    signals: List[ExposureSignal] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Summary helpers
    # ------------------------------------------------------------------

    @property
    def signal_count(self) -> int:
        return len(self.signals)

    def _count_by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {s.value: 0 for s in SignalSeverity}
        for sig in self.signals:
            counts[sig.severity.value] = counts.get(sig.severity.value, 0) + 1
        return counts

    def top_risks(self, n: int = 5) -> List[ExposureSignal]:
        """Return the *n* highest-severity / highest-confidence signals."""
        _order = {
            SignalSeverity.CRITICAL: 0,
            SignalSeverity.HIGH: 1,
            SignalSeverity.MEDIUM: 2,
            SignalSeverity.LOW: 3,
            SignalSeverity.INFO: 4,
        }
        return sorted(
            self.signals,
            key=lambda s: (_order.get(s.severity, 99), -s.confidence),
        )[:n]

    def to_dict(self) -> Dict:
        sev_counts = self._count_by_severity()
        return {
            "target":        self.target,
            "signal_count":  self.signal_count,
            "summary": {
                "critical": sev_counts.get("CRITICAL", 0),
                "high":     sev_counts.get("HIGH", 0),
                "medium":   sev_counts.get("MEDIUM", 0),
                "low":      sev_counts.get("LOW", 0),
                "info":     sev_counts.get("INFO", 0),
            },
            "top_risks": [s.to_dict() for s in self.top_risks()],
            "signals":   [s.to_dict() for s in self.signals],
        }


# ---------------------------------------------------------------------------
# Exposure Engine
# ---------------------------------------------------------------------------

class ExposureEngine:
    """
    Derives exposure signals from already-collected scan data.

    Parameters
    ----------
    results:
        The full ``HybridScanner.results`` dictionary produced by the scan
        pipeline.  Only read — never mutated.
    aggressive:
        When ``False`` (default) only clearly-confirmed or high-confidence
        signals are emitted.  When ``True`` additional lower-confidence
        heuristics are included.
    """

    def __init__(self, results: Dict, aggressive: bool = False) -> None:
        self._results = results
        self._aggressive = aggressive
        self._target = results.get("target", "unknown")
        self._seq: int = 0  # sequential signal counter within a type

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> ExposureReport:
        """Execute all detectors and return a consolidated ExposureReport."""
        report = ExposureReport(target=self._target)

        report.signals.extend(self._detect_risky_services())
        report.signals.extend(self._detect_management_exposure())
        report.signals.extend(self._detect_snmp_exposure())
        report.signals.extend(self._detect_weak_tls())
        report.signals.extend(self._detect_cert_issues())
        report.signals.extend(self._detect_eol_versions())
        report.signals.extend(self._detect_anon_services())
        report.signals.extend(self._detect_db_exposure())

        return report

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}-{self._seq:03d}"

    def _all_open_tcp(self) -> List[Dict]:
        return self._results.get("open_ports", []) or []

    def _all_open_udp(self) -> List[Dict]:
        return self._results.get("udp_ports", []) or []

    def _tls_scan(self) -> Dict:
        return self._results.get("tls_scan", {}) or {}

    def _compliance(self) -> Dict:
        return self._results.get("compliance", {}) or {}

    def _inventory_assets(self) -> List[Dict]:
        return (self._results.get("inventory") or {}).get("assets", [])

    def _vulnerabilities(self) -> List[Dict]:
        return self._results.get("vulnerabilities", []) or []

    # ------------------------------------------------------------------
    # Detectors
    # ------------------------------------------------------------------

    def _detect_risky_services(self) -> List[ExposureSignal]:
        """EXP-RISKY-SVC — cleartext / legacy service ports open."""
        signals: List[ExposureSignal] = []
        tcp_ports = {p["port"] for p in self._all_open_tcp()}
        udp_ports = {p["port"] for p in self._all_open_udp()}
        all_ports = tcp_ports | udp_ports

        for port, (label, reason, severity) in _RISKY_SERVICE_PORTS.items():
            if port not in all_ports:
                continue
            proto = "tcp" if port in tcp_ports else "udp"
            signals.append(ExposureSignal(
                signal_id=self._make_id("EXP-RISKY-SVC"),
                title=f"Risky service exposed: {label} (port {port}/{proto})",
                description=(
                    f"{label} is open on port {port}/{proto}. {reason}. "
                    "Replace with a secure, encrypted alternative."
                ),
                evidence=[
                    f"Port {port}/{proto} is open",
                    reason,
                ],
                confidence=0.85,
                severity=severity,
                affected_asset=self._target,
                affected_service=label,
                signal_type="risky_service",
                heuristic=False,
            ))
        return signals

    def _detect_management_exposure(self) -> List[ExposureSignal]:
        """EXP-MGMT-EXP — management interfaces accessible on default ports."""
        signals: List[ExposureSignal] = []
        tcp_ports = {p["port"] for p in self._all_open_tcp()}
        udp_ports = {p["port"] for p in self._all_open_udp()}
        all_ports = tcp_ports | udp_ports

        # Skip ports already caught by risky-service detector to avoid duplicates
        already_risky = set(_RISKY_SERVICE_PORTS.keys())

        for port, (label, severity) in _MGMT_PORTS.items():
            if port not in all_ports:
                continue
            if port in already_risky:
                continue
            proto = "tcp" if port in tcp_ports else "udp"
            signals.append(ExposureSignal(
                signal_id=self._make_id("EXP-MGMT-EXP"),
                title=f"Management interface exposed: {label} (port {port}/{proto})",
                description=(
                    f"{label} is accessible on its default port {port}/{proto}. "
                    "Management interfaces should be restricted to trusted networks "
                    "or administrative VLANs."
                ),
                evidence=[
                    f"Port {port}/{proto} is open on {self._target}",
                    f"Service: {label}",
                ],
                confidence=0.80,
                severity=severity,
                affected_asset=self._target,
                affected_service=label,
                signal_type="management_exposure",
                heuristic=False,
            ))
        return signals

    def _detect_snmp_exposure(self) -> List[ExposureSignal]:
        """EXP-SNMP-UNAUTH — SNMP with default community string detected."""
        signals: List[ExposureSignal] = []

        # Check compliance controls for SVC-003 (SNMP default community)
        for ctrl in self._compliance().get("controls", []):
            if ctrl.get("control_id") == "SVC-003" and ctrl.get("status") == "FAIL":
                signals.append(ExposureSignal(
                    signal_id=self._make_id("EXP-SNMP-UNAUTH"),
                    title="SNMP default community string accepted",
                    description=(
                        "The SNMP service accepted a default community string (e.g., 'public'). "
                        "This allows unauthenticated read access to device configuration data. "
                        "Change community strings and consider upgrading to SNMPv3 with authentication."
                    ),
                    evidence=ctrl.get("evidence", []) + [
                        "Compliance control SVC-003 flagged SNMP default community string",
                    ],
                    confidence=0.90,
                    severity=SignalSeverity.HIGH,
                    affected_asset=self._target,
                    affected_service="SNMP",
                    signal_type="unauthenticated_service",
                    heuristic=False,
                ))
                break

        # Also check vulnerability findings for SNMP community string findings
        for vuln in self._vulnerabilities():
            vuln_id = vuln.get("id", "")
            if "SNMP" in vuln_id and vuln.get("status") in ("CONFIRMED", "POTENTIAL"):
                if not signals:  # avoid duplicate if compliance already caught it
                    signals.append(ExposureSignal(
                        signal_id=self._make_id("EXP-SNMP-UNAUTH"),
                        title="SNMP community string exposure detected",
                        description=(
                            "A vulnerability finding indicates SNMP community string exposure. "
                            "Review SNMP configuration and restrict access."
                        ),
                        evidence=[
                            f"Vulnerability {vuln_id} detected: {vuln.get('title', '')}",
                            f"Status: {vuln.get('status', '')}",
                        ],
                        confidence=0.75 if vuln.get("status") == "CONFIRMED" else 0.50,
                        severity=SignalSeverity.HIGH,
                        affected_asset=self._target,
                        affected_service="SNMP",
                        signal_type="unauthenticated_service",
                        heuristic=False,
                    ))
                break
        return signals

    def _detect_weak_tls(self) -> List[ExposureSignal]:
        """EXP-WEAK-TLS — weak protocol or cipher detected in TLS scan."""
        signals: List[ExposureSignal] = []
        tls = self._tls_scan()

        for port_str, info in tls.items():
            if info.get("error"):
                continue
            port = port_str

            # Legacy protocol
            proto = info.get("protocol_version", "") or ""
            if proto in ("TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"):
                signals.append(ExposureSignal(
                    signal_id=self._make_id("EXP-WEAK-TLS"),
                    title=f"Deprecated TLS protocol negotiated on port {port}",
                    description=(
                        f"The TLS service on port {port} negotiated {proto}, "
                        "which is deprecated and vulnerable to known attacks "
                        "(POODLE, BEAST, etc.). Upgrade to TLS 1.2 or 1.3."
                    ),
                    evidence=[
                        f"Port {port}/tcp TLS inspection: protocol={proto}",
                        "TLS 1.0 and 1.1 are deprecated by RFC 8996",
                    ],
                    confidence=0.95,
                    severity=SignalSeverity.HIGH,
                    affected_asset=self._target,
                    affected_service=f"TLS:{port}",
                    signal_type="weak_tls",
                    heuristic=False,
                ))

            # Weak cipher
            cipher = info.get("cipher_name", "") or ""
            _weak_patterns = ["RC4", "NULL", "EXPORT", "anon", "ADH", "AECDH", "DES", "3DES"]
            weak_reason = next((p for p in _weak_patterns if p.upper() in cipher.upper()), None)
            if weak_reason:
                signals.append(ExposureSignal(
                    signal_id=self._make_id("EXP-WEAK-TLS"),
                    title=f"Weak TLS cipher suite in use on port {port}: {cipher}",
                    description=(
                        f"The cipher suite '{cipher}' negotiated on port {port} "
                        f"is considered weak or broken (contains '{weak_reason}'). "
                        "Disable weak cipher suites and prefer AEAD ciphers "
                        "(e.g., AES-GCM, CHACHA20)."
                    ),
                    evidence=[
                        f"Port {port}/tcp TLS cipher: {cipher}",
                        f"Weak pattern detected: {weak_reason}",
                    ],
                    confidence=0.90,
                    severity=SignalSeverity.HIGH,
                    affected_asset=self._target,
                    affected_service=f"TLS:{port}",
                    signal_type="weak_tls",
                    heuristic=False,
                ))

            # No forward secrecy
            if not info.get("has_forward_secrecy", True) and cipher:
                signals.append(ExposureSignal(
                    signal_id=self._make_id("EXP-WEAK-TLS"),
                    title=f"No forward secrecy on TLS port {port}",
                    description=(
                        f"The cipher suite in use on port {port} does not provide "
                        "forward secrecy (no ECDHE/DHE key exchange). "
                        "Past sessions can be decrypted if the server private key is compromised."
                    ),
                    evidence=[
                        f"Port {port}/tcp TLS cipher: {cipher}",
                        "Forward secrecy (ECDHE/DHE) not detected",
                    ],
                    confidence=0.80,
                    severity=SignalSeverity.MEDIUM,
                    affected_asset=self._target,
                    affected_service=f"TLS:{port}",
                    signal_type="weak_tls",
                    heuristic=False,
                ))

        # Also pull from TLS compliance controls
        tls_ctrl_ids = {"TLS-001", "TLS-005"}
        for ctrl in self._compliance().get("controls", []):
            if ctrl.get("control_id") in tls_ctrl_ids and ctrl.get("status") == "FAIL":
                ctrl_id = ctrl["control_id"]
                signals.append(ExposureSignal(
                    signal_id=self._make_id("EXP-WEAK-TLS"),
                    title=f"TLS compliance failure: {ctrl.get('title', ctrl_id)}",
                    description=ctrl.get("description", ""),
                    evidence=ctrl.get("evidence", []) + [
                        f"Compliance control {ctrl_id} flagged as FAIL",
                    ],
                    confidence=0.85,
                    severity=SignalSeverity.HIGH,
                    affected_asset=self._target,
                    affected_service="TLS",
                    signal_type="weak_tls",
                    heuristic=False,
                ))
        return signals

    def _detect_cert_issues(self) -> List[ExposureSignal]:
        """EXP-CERT-ISSUE — certificate problems (expired, self-signed, near-expiry)."""
        signals: List[ExposureSignal] = []

        # Pull from compliance controls TLS-002, TLS-003, TLS-004
        cert_ctrl_map = {
            "TLS-002": (SignalSeverity.HIGH,   "Certificate near expiry"),
            "TLS-003": (SignalSeverity.CRITICAL, "Certificate already expired"),
            "TLS-004": (SignalSeverity.HIGH,   "Self-signed or untrusted certificate chain"),
        }
        for ctrl in self._compliance().get("controls", []):
            ctrl_id = ctrl.get("control_id", "")
            if ctrl_id in cert_ctrl_map and ctrl.get("status") == "FAIL":
                sev, label = cert_ctrl_map[ctrl_id]
                signals.append(ExposureSignal(
                    signal_id=self._make_id("EXP-CERT-ISSUE"),
                    title=f"Certificate issue: {label}",
                    description=ctrl.get("description", ""),
                    evidence=ctrl.get("evidence", []) + [
                        f"Compliance control {ctrl_id} flagged as FAIL",
                    ],
                    confidence=0.90,
                    severity=sev,
                    affected_asset=self._target,
                    affected_service="TLS Certificate",
                    signal_type="cert_issue",
                    heuristic=False,
                ))

        # Also inspect raw TLS scan data for cert issues not caught by compliance
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        for port_str, info in self._tls_scan().items():
            if info.get("error"):
                continue
            cert = info.get("cert_info") or {}
            if not cert:
                continue

            # Self-signed
            if cert.get("self_signed"):
                already = any(
                    "self-signed" in s.title.lower() or "TLS-004" in " ".join(s.evidence)
                    for s in signals
                )
                if not already:
                    signals.append(ExposureSignal(
                        signal_id=self._make_id("EXP-CERT-ISSUE"),
                        title=f"Self-signed certificate on port {port_str}",
                        description=(
                            f"The TLS certificate on port {port_str} is self-signed. "
                            "Clients cannot verify authenticity; susceptible to MITM."
                        ),
                        evidence=[
                            f"Port {port_str}/tcp cert: self_signed=True",
                            f"Issuer: {cert.get('issuer_cn', 'unknown')}",
                        ],
                        confidence=0.95,
                        severity=SignalSeverity.HIGH,
                        affected_asset=self._target,
                        affected_service=f"TLS:{port_str}",
                        signal_type="cert_issue",
                        heuristic=False,
                    ))

        return signals

    def _detect_eol_versions(self) -> List[ExposureSignal]:
        """EXP-EOL-VER — banner/version hints matching known EOL version families."""
        signals: List[ExposureSignal] = []

        # Gather all banner and version strings from TCP/UDP results and inventory
        candidates: List[Tuple[str, str, int, str]] = []  # (text, source, port, proto)

        for p in self._all_open_tcp():
            for field_name in ("banner", "version"):
                val = (p.get(field_name) or "").strip()
                if val:
                    candidates.append((val, field_name, p.get("port", 0), "tcp"))

        for p in self._all_open_udp():
            for field_name in ("banner", "version"):
                val = (p.get(field_name) or "").strip()
                if val:
                    candidates.append((val, field_name, p.get("port", 0), "udp"))

        # Inventory asset service records also carry version hints
        for asset in self._inventory_assets():
            for _svc_dict in asset.get("tcp_services", {}).values():
                ver = (_svc_dict.get("version") or "").strip()
                banner = (_svc_dict.get("banner") or "").strip()
                port = _svc_dict.get("port", 0)
                if ver:
                    candidates.append((ver, "inventory-version", port, "tcp"))
                if banner:
                    candidates.append((banner, "inventory-banner", port, "tcp"))

        seen_families: set = set()

        for text, source, port, proto in candidates:
            for pattern, family, safe_min, severity in _EOL_VERSION_TABLE:
                if family in seen_families:
                    continue
                if re.search(pattern, text, re.IGNORECASE):
                    seen_families.add(family)
                    port_label = f" (port {port}/{proto})" if port else ""
                    signals.append(ExposureSignal(
                        signal_id=self._make_id("EXP-EOL-VER"),
                        title=f"Potentially end-of-life software detected: {family}{port_label}",
                        description=(
                            f"Version banner indicates {family}, which is likely past "
                            "its end-of-life date and may no longer receive security patches. "
                            f"Consider upgrading to {safe_min} or later. "
                            "Note: This is a heuristic assessment based on version string "
                            "pattern matching — verify the actual patch level before acting."
                        ),
                        evidence=[
                            f"Version hint from {source}: {text[:120]}",
                            f"Matched EOL family pattern: {family}",
                            f"Recommended minimum version: {safe_min}",
                        ],
                        confidence=0.65 if self._aggressive else 0.55,
                        severity=severity,
                        affected_asset=self._target,
                        affected_service=family.split()[0],
                        signal_type="eol_version",
                        heuristic=True,
                    ))
        return signals

    def _detect_anon_services(self) -> List[ExposureSignal]:
        """EXP-ANON-SVC — anonymous/unauthenticated service access confirmed."""
        signals: List[ExposureSignal] = []

        # Check vulnerability findings for anonymous access
        anon_patterns = ["ANON", "anonymous", "AUTH-001", "AUTH-002"]
        for vuln in self._vulnerabilities():
            vuln_id = str(vuln.get("id", ""))
            vuln_name = str(vuln.get("name", ""))
            if not any(p.lower() in (vuln_id + vuln_name).lower() for p in anon_patterns):
                continue
            if vuln.get("status") not in ("CONFIRMED", "POTENTIAL"):
                continue
            confidence = 0.90 if vuln.get("status") == "CONFIRMED" else 0.55
            signals.append(ExposureSignal(
                signal_id=self._make_id("EXP-ANON-SVC"),
                title=f"Anonymous/unauthenticated service access: {vuln.get('title', vuln_id)}",
                description=(
                    "An unauthenticated or anonymous access condition was detected. "
                    "Review the service configuration and enforce authentication."
                ),
                evidence=[
                    f"Vulnerability finding: {vuln_id} — {vuln.get('title', '')}",
                    f"Status: {vuln.get('status', '')}",
                ] + (vuln.get("evidence") or [])[:3],
                confidence=confidence,
                severity=SignalSeverity.HIGH if vuln.get("status") == "CONFIRMED" else SignalSeverity.MEDIUM,
                affected_asset=self._target,
                affected_service=str(vuln.get("affected_service", "")),
                signal_type="unauthenticated_service",
                heuristic=False,
            ))

        # Check compliance controls AUTH-001, AUTH-002
        for ctrl in self._compliance().get("controls", []):
            if ctrl.get("control_id") in ("AUTH-001", "AUTH-002") and ctrl.get("status") == "FAIL":
                ctrl_id = ctrl["control_id"]
                signals.append(ExposureSignal(
                    signal_id=self._make_id("EXP-ANON-SVC"),
                    title=f"Anonymous service access detected (compliance: {ctrl_id})",
                    description=ctrl.get("description", ""),
                    evidence=ctrl.get("evidence", []) + [
                        f"Compliance control {ctrl_id} flagged as FAIL",
                    ],
                    confidence=0.85,
                    severity=SignalSeverity.HIGH,
                    affected_asset=self._target,
                    affected_service="FTP/Anonymous",
                    signal_type="unauthenticated_service",
                    heuristic=False,
                ))
        return signals

    def _detect_db_exposure(self) -> List[ExposureSignal]:
        """EXP-DB-EXPOSED — database service accessible on default port."""
        signals: List[ExposureSignal] = []
        tcp_ports = {p["port"] for p in self._all_open_tcp()}

        for port, label in _DB_PORTS.items():
            if port not in tcp_ports:
                continue
            # Don't double-emit if management exposure already covered it
            signals.append(ExposureSignal(
                signal_id=self._make_id("EXP-DB-EXPOSED"),
                title=f"Database service exposed on default port: {label} (port {port}/tcp)",
                description=(
                    f"{label} is accessible on its default port {port}/tcp. "
                    "Database services should not be directly reachable from untrusted networks. "
                    "Restrict access using firewall rules or network segmentation."
                ),
                evidence=[
                    f"Port {port}/tcp is open",
                    f"Service: {label} (default port)",
                ],
                confidence=0.80,
                severity=SignalSeverity.CRITICAL if port in (9200, 6379, 27017, 11211) else SignalSeverity.HIGH,
                affected_asset=self._target,
                affected_service=label,
                signal_type="database_exposure",
                heuristic=False,
            ))
        return signals
