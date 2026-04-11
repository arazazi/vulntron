"""
Compliance & configuration baseline posture module for Vultron PR5.

Provides a lightweight compliance check framework that runs safe, non-invasive
controls against data already gathered by earlier scan phases (TCP ports, TLS
inspection, UDP ports, auth-scan results) and maps results into a structured
compliance report section.

Design goals
------------
- Separate from vulnerability findings but compatible with the unified result dict.
- Each control has a stable ID, description, rationale, evidence list, and a
  pass/fail/unknown/skip status with an optional severity/priority.
- Controls are grouped into named profiles ("baseline", "server", "workstation").
- Credential-aware: controls that require authenticated data declare the need and
  are automatically skipped/marked unknown when credentials are absent.
- No offensive checks; read-only analysis of already-collected data.
- Secrets must never appear in evidence strings (callers must pre-redact).

Compliance control IDs
----------------------
TLS-001  Deprecated TLS protocol in use (TLS 1.0 / TLS 1.1)
TLS-002  Certificate expiry within warning window (≤ 30 days)
TLS-003  Certificate already expired
TLS-004  Self-signed or untrusted certificate chain detected
TLS-005  Weak / deprecated cipher suite in use
SVC-001  Telnet service exposed (cleartext remote access)
SVC-002  FTP service exposed
SVC-003  SNMP default community string accepted
SVC-004  Risky high-risk service port exposed (Rsh/Rlogin/Rexec/TFTP/NFS/…)
AUTH-001 Anonymous FTP login accepted
AUTH-002 Anonymous service detected on scanning data (conservative)
OS-001   OS patch posture (placeholder — credentialed data required)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Status / severity enumerations
# ---------------------------------------------------------------------------

class ControlStatus(str, Enum):
    """Possible outcomes for a single compliance control evaluation."""
    PASS    = "PASS"
    FAIL    = "FAIL"
    UNKNOWN = "UNKNOWN"  # data insufficient to determine compliance
    SKIP    = "SKIP"     # control explicitly skipped (e.g. creds missing)


class ControlSeverity(str, Enum):
    """Priority / severity of a failing control."""
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


# ---------------------------------------------------------------------------
# Core data model
# ---------------------------------------------------------------------------

@dataclass
class ComplianceControl:
    """A single compliance/configuration check."""
    control_id:           str
    title:                str
    description:          str
    rationale:            str
    status:               ControlStatus = ControlStatus.UNKNOWN
    severity:             ControlSeverity = ControlSeverity.MEDIUM
    evidence:             List[str] = field(default_factory=list)
    skip_reason:          Optional[str] = None
    requires_credentials: bool = False

    def to_dict(self) -> Dict:
        return {
            "control_id":           self.control_id,
            "title":                self.title,
            "description":          self.description,
            "rationale":            self.rationale,
            "status":               self.status.value,
            "severity":             self.severity.value,
            "evidence":             list(self.evidence),
            "skip_reason":          self.skip_reason,
            "requires_credentials": self.requires_credentials,
        }

    def _pass(self, evidence: str) -> "ComplianceControl":
        self.status = ControlStatus.PASS
        if evidence:
            self.evidence.append(evidence)
        return self

    def _fail(self, evidence: str) -> "ComplianceControl":
        self.status = ControlStatus.FAIL
        if evidence:
            self.evidence.append(evidence)
        return self

    def _skip(self, reason: str) -> "ComplianceControl":
        self.status = ControlStatus.SKIP
        self.skip_reason = reason
        return self

    def _unknown(self, reason: str) -> "ComplianceControl":
        self.status = ControlStatus.UNKNOWN
        self.skip_reason = reason
        return self


# ---------------------------------------------------------------------------
# Profile definition
# ---------------------------------------------------------------------------

PROFILE_CONTROLS: Dict[str, List[str]] = {
    "baseline": [
        "TLS-001", "TLS-002", "TLS-003", "TLS-004", "TLS-005",
        "SVC-001", "SVC-002", "SVC-003", "SVC-004",
        "AUTH-001", "AUTH-002",
        "OS-001",
    ],
    "server": [
        "TLS-001", "TLS-002", "TLS-003", "TLS-004", "TLS-005",
        "SVC-001", "SVC-002", "SVC-003", "SVC-004",
        "AUTH-001", "AUTH-002",
        "OS-001",
    ],
    "workstation": [
        "SVC-001", "SVC-002", "SVC-004",
        "AUTH-001", "AUTH-002",
        "OS-001",
    ],
}

ALL_PROFILES: Set[str] = set(PROFILE_CONTROLS.keys())

# ---------------------------------------------------------------------------
# Risky service port catalogue
# ---------------------------------------------------------------------------

# Ports that should rarely be exposed publicly. Checked by SVC-004.
_RISKY_PORTS: Dict[int, str] = {
    512:  "rexec (cleartext remote exec)",
    513:  "rlogin (cleartext remote login)",
    514:  "rsh / syslog (cleartext remote shell / unauth syslog)",
    69:   "TFTP (unauthenticated file transfer)",
    2049: "NFS (unauthenticated/low-auth file access)",
    111:  "portmapper/rpcbind (RPC enumeration pivot)",
    135:  "MS-RPC endpoint mapper",
    137:  "NetBIOS Name Service",
    139:  "NetBIOS Session Service (legacy SMB)",
    1900: "SSDP / UPnP (unauthenticated device announcement)",
    5900: "VNC (often no/weak auth)",
    6000: "X11 (unencrypted display server)",
}

# Weak TLS protocol version strings to flag as deprecated
_WEAK_TLS_PROTOCOLS: Set[str] = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"}

# Weak / deprecated cipher patterns (case-insensitive substring match)
_WEAK_CIPHER_PATTERNS: List[str] = [
    r"\bRC4\b", r"\bNULL\b", r"\bEXPORT\b", r"ANON", r"_anon_",
    r"\b3DES\b", r"DES-CBC3",
]

# Cert-expiry warning threshold (days)
_CERT_EXPIRY_WARN_DAYS = 30


# ---------------------------------------------------------------------------
# Baseline compliance checker
# ---------------------------------------------------------------------------

class BaselineComplianceChecker:
    """
    Evaluates a set of baseline compliance controls against collected scan data.

    Parameters
    ----------
    scan_results : dict
        The ``results`` dict produced by ``HybridScanner.run()``.
    profile : str
        Profile name.  Must be one of :data:`ALL_PROFILES`.
    has_credentials : bool
        ``True`` when at least one credential set was provided and attempted.
    """

    def __init__(
        self,
        scan_results: Dict,
        profile: str = "baseline",
        has_credentials: bool = False,
    ) -> None:
        self._results       = scan_results
        self._profile       = profile if profile in ALL_PROFILES else "baseline"
        self._has_creds     = has_credentials
        self._controls: List[ComplianceControl] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> "ComplianceReport":
        """Execute all controls for the selected profile and return a report."""
        control_ids = PROFILE_CONTROLS.get(self._profile, PROFILE_CONTROLS["baseline"])
        for cid in control_ids:
            method = getattr(self, f"_check_{cid.replace('-', '_').lower()}", None)
            if method is None:
                continue
            ctrl = method()
            self._controls.append(ctrl)
        return ComplianceReport(
            profile=self._profile,
            target=self._results.get("target", "unknown"),
            controls=list(self._controls),
        )

    # ------------------------------------------------------------------
    # TLS controls
    # ------------------------------------------------------------------

    def _check_tls_001(self) -> ComplianceControl:
        """TLS-001: Deprecated TLS protocol detected."""
        ctrl = ComplianceControl(
            control_id="TLS-001",
            title="Deprecated TLS Protocol In Use",
            description=(
                "One or more ports accepted a TLS handshake using TLS 1.0 or TLS 1.1, "
                "both of which are deprecated and no longer considered secure."
            ),
            rationale=(
                "TLS 1.0 and 1.1 are vulnerable to protocol-level attacks (BEAST, POODLE). "
                "All services should negotiate TLS 1.2 or TLS 1.3 only."
            ),
            severity=ControlSeverity.HIGH,
        )
        tls_scan: Dict = self._results.get("tls_scan") or {}
        if not tls_scan:
            return ctrl._unknown("No TLS inspection data available")

        failing_ports = []
        for port_str, info in tls_scan.items():
            if info.get("error"):
                continue
            proto = info.get("protocol_version") or info.get("protocol_display") or ""
            if proto in _WEAK_TLS_PROTOCOLS:
                failing_ports.append(f"port {port_str} ({proto})")
        if failing_ports:
            ctrl._fail(f"Deprecated TLS protocol detected on: {', '.join(failing_ports)}")
        else:
            ctrl._pass("All inspected TLS ports use TLS 1.2 or later")
        return ctrl

    def _check_tls_002(self) -> ComplianceControl:
        """TLS-002: Certificate expiry within warning window."""
        ctrl = ComplianceControl(
            control_id="TLS-002",
            title=f"Certificate Expiring Within {_CERT_EXPIRY_WARN_DAYS} Days",
            description=(
                f"At least one certificate expires within {_CERT_EXPIRY_WARN_DAYS} days. "
                "Expired certificates will cause TLS failures and user trust errors."
            ),
            rationale=(
                "Certificates should be renewed well before expiry to avoid unplanned "
                "outages and man-in-the-middle exposure windows."
            ),
            severity=ControlSeverity.MEDIUM,
        )
        tls_scan: Dict = self._results.get("tls_scan") or {}
        if not tls_scan:
            return ctrl._unknown("No TLS inspection data available")

        now = datetime.now(timezone.utc)
        warning_ports = []
        for port_str, info in tls_scan.items():
            if info.get("error"):
                continue
            cert = info.get("cert_info") or {}
            not_after_str = cert.get("not_after") or ""
            if not not_after_str:
                continue
            try:
                not_after = datetime.fromisoformat(not_after_str.replace("Z", "+00:00"))
                if not_after.tzinfo is None:
                    not_after = not_after.replace(tzinfo=timezone.utc)
            except (ValueError, AttributeError):
                continue
            days_left = (not_after - now).days
            if 0 <= days_left <= _CERT_EXPIRY_WARN_DAYS:
                warning_ports.append(f"port {port_str} (expires in {days_left}d)")
        if warning_ports:
            ctrl._fail(f"Certificate expiring soon: {', '.join(warning_ports)}")
        else:
            ctrl._pass(
                f"All inspected certificates expire more than {_CERT_EXPIRY_WARN_DAYS} days out"
            )
        return ctrl

    def _check_tls_003(self) -> ComplianceControl:
        """TLS-003: Certificate already expired."""
        ctrl = ComplianceControl(
            control_id="TLS-003",
            title="Expired Certificate Detected",
            description=(
                "At least one certificate has already passed its not-after date. "
                "TLS clients will reject connections to this service."
            ),
            rationale=(
                "Expired certificates indicate a lapsed renewal process and may "
                "allow attackers to present substitute certificates without detection."
            ),
            severity=ControlSeverity.HIGH,
        )
        tls_scan: Dict = self._results.get("tls_scan") or {}
        if not tls_scan:
            return ctrl._unknown("No TLS inspection data available")

        now = datetime.now(timezone.utc)
        expired_ports = []
        for port_str, info in tls_scan.items():
            if info.get("error"):
                continue
            cert = info.get("cert_info") or {}
            not_after_str = cert.get("not_after") or ""
            if not not_after_str:
                continue
            try:
                not_after = datetime.fromisoformat(not_after_str.replace("Z", "+00:00"))
                if not_after.tzinfo is None:
                    not_after = not_after.replace(tzinfo=timezone.utc)
            except (ValueError, AttributeError):
                continue
            if not_after < now:
                expired_ports.append(f"port {port_str} (expired {not_after.date()})")
        if expired_ports:
            ctrl._fail(f"Expired certificate on: {', '.join(expired_ports)}")
        else:
            ctrl._pass("No expired certificates detected")
        return ctrl

    def _check_tls_004(self) -> ComplianceControl:
        """TLS-004: Self-signed / untrusted certificate chain."""
        ctrl = ComplianceControl(
            control_id="TLS-004",
            title="Self-Signed or Untrusted Certificate Chain",
            description=(
                "At least one port presented a self-signed certificate or a chain "
                "that could not be validated against a trusted root."
            ),
            rationale=(
                "Self-signed certificates do not provide third-party identity assurance "
                "and are susceptible to man-in-the-middle attacks."
            ),
            severity=ControlSeverity.MEDIUM,
        )
        tls_scan: Dict = self._results.get("tls_scan") or {}
        if not tls_scan:
            return ctrl._unknown("No TLS inspection data available")

        untrusted_ports = []
        for port_str, info in tls_scan.items():
            if info.get("error"):
                continue
            cert = info.get("cert_info") or {}
            if cert.get("is_self_signed"):
                untrusted_ports.append(f"port {port_str} (self-signed)")
            elif cert and not cert.get("chain_trusted", True):
                untrusted_ports.append(f"port {port_str} (untrusted chain)")
        if untrusted_ports:
            ctrl._fail(f"Untrusted certificate on: {', '.join(untrusted_ports)}")
        else:
            ctrl._pass("All inspected certificates have a trusted chain")
        return ctrl

    def _check_tls_005(self) -> ComplianceControl:
        """TLS-005: Weak / deprecated cipher suite."""
        ctrl = ComplianceControl(
            control_id="TLS-005",
            title="Weak or Deprecated Cipher Suite In Use",
            description=(
                "At least one port negotiated a cipher suite known to be weak or deprecated "
                "(e.g., RC4, NULL, EXPORT, anonymous, 3DES)."
            ),
            rationale=(
                "Weak ciphers provide inadequate confidentiality or integrity. "
                "Services should be configured to offer only strong ciphers."
            ),
            severity=ControlSeverity.HIGH,
        )
        tls_scan: Dict = self._results.get("tls_scan") or {}
        if not tls_scan:
            return ctrl._unknown("No TLS inspection data available")

        weak_ports = []
        for port_str, info in tls_scan.items():
            if info.get("error"):
                continue
            cipher = info.get("cipher_name") or ""
            for pattern in _WEAK_CIPHER_PATTERNS:
                if re.search(pattern, cipher, re.IGNORECASE):
                    weak_ports.append(f"port {port_str} ({cipher})")
                    break
        if weak_ports:
            ctrl._fail(f"Weak cipher suite on: {', '.join(weak_ports)}")
        else:
            ctrl._pass("No weak cipher suites detected on inspected ports")
        return ctrl

    # ------------------------------------------------------------------
    # Service exposure controls
    # ------------------------------------------------------------------

    def _check_svc_001(self) -> ComplianceControl:
        """SVC-001: Telnet service exposed."""
        ctrl = ComplianceControl(
            control_id="SVC-001",
            title="Telnet Service Exposed",
            description=(
                "Port 23/TCP (Telnet) is open. Telnet transmits all data, including "
                "credentials, in cleartext and should not be reachable from untrusted networks."
            ),
            rationale=(
                "Telnet provides no confidentiality or integrity protection. "
                "Replace with SSH for all remote management."
            ),
            severity=ControlSeverity.HIGH,
        )
        open_ports = self._results.get("open_ports") or []
        telnet_open = any(p.get("port") == 23 for p in open_ports)
        if telnet_open:
            ctrl._fail("Port 23/TCP (Telnet) is open and accessible")
        else:
            ctrl._pass("Port 23/TCP (Telnet) is not open")
        return ctrl

    def _check_svc_002(self) -> ComplianceControl:
        """SVC-002: FTP service exposed."""
        ctrl = ComplianceControl(
            control_id="SVC-002",
            title="FTP Service Exposed",
            description=(
                "Port 21/TCP (FTP) is open. FTP transmits credentials and data in cleartext "
                "unless explicitly secured with FTPS or replaced with SFTP."
            ),
            rationale=(
                "FTP provides no confidentiality. Use SFTP (SSH file transfer) or FTPS "
                "with mandatory TLS for all file transfer needs."
            ),
            severity=ControlSeverity.MEDIUM,
        )
        open_ports = self._results.get("open_ports") or []
        ftp_open = any(p.get("port") == 21 for p in open_ports)
        if ftp_open:
            ctrl._fail("Port 21/TCP (FTP) is open and accessible")
        else:
            ctrl._pass("Port 21/TCP (FTP) is not open")
        return ctrl

    def _check_svc_003(self) -> ComplianceControl:
        """SVC-003: SNMP default community string accepted."""
        ctrl = ComplianceControl(
            control_id="SVC-003",
            title="SNMP Default Community String Accepted",
            description=(
                "The SNMP service accepted a probe using a default community string "
                "('public' or 'private'), indicating default credentials have not been changed."
            ),
            rationale=(
                "Default SNMP community strings are widely known and allow read (or write) "
                "access to device configuration and status. Change all community strings."
            ),
            severity=ControlSeverity.HIGH,
        )
        vulns = self._results.get("vulnerabilities") or []
        snmp_confirmed = any(
            "snmp" in (v.get("name") or "").lower()
            and v.get("status") == "CONFIRMED"
            for v in vulns
        )
        snmp_port_open = any(
            p.get("port") == 161
            for p in (self._results.get("udp_ports") or [])
        )
        if snmp_confirmed:
            ctrl._fail("SNMP default community string was accepted (CONFIRMED finding)")
        elif snmp_port_open:
            ctrl._unknown(
                "SNMP port 161/UDP is open but community string status is not confirmed"
            )
        else:
            ctrl._pass("SNMP port 161/UDP not detected as open")
        return ctrl

    def _check_svc_004(self) -> ComplianceControl:
        """SVC-004: Risky legacy service port exposed."""
        ctrl = ComplianceControl(
            control_id="SVC-004",
            title="High-Risk Legacy Service Port Exposed",
            description=(
                "One or more high-risk service ports are open (e.g., rsh, rlogin, rexec, "
                "TFTP, NFS, portmapper, VNC, X11). These services have weak or absent "
                "authentication and should not be accessible from untrusted networks."
            ),
            rationale=(
                "Legacy remote-access and file-sharing services provide minimal security "
                "guarantees and are frequent targets for lateral movement."
            ),
            severity=ControlSeverity.HIGH,
        )
        all_ports = (
            [(p.get("port"), "tcp") for p in (self._results.get("open_ports") or [])]
            + [(p.get("port"), "udp") for p in (self._results.get("udp_ports") or [])]
        )
        found = []
        for port_num, proto in all_ports:
            if port_num in _RISKY_PORTS:
                found.append(f"port {port_num}/{proto} ({_RISKY_PORTS[port_num]})")
        if found:
            ctrl._fail(f"Risky ports detected: {'; '.join(found)}")
        else:
            ctrl._pass("No high-risk legacy service ports detected")
        return ctrl

    # ------------------------------------------------------------------
    # Authentication posture controls
    # ------------------------------------------------------------------

    def _check_auth_001(self) -> ComplianceControl:
        """AUTH-001: Anonymous FTP login accepted."""
        ctrl = ComplianceControl(
            control_id="AUTH-001",
            title="Anonymous FTP Login Accepted",
            description=(
                "The FTP service accepted an anonymous login attempt, allowing "
                "unauthenticated access to the file system exposed by the FTP server."
            ),
            rationale=(
                "Anonymous FTP access should be disabled unless explicitly required "
                "and tightly scoped; it exposes data without any identity accountability."
            ),
            severity=ControlSeverity.HIGH,
        )
        vulns = self._results.get("vulnerabilities") or []
        anon_ftp_confirmed = any(
            "anonymous" in (v.get("name") or "").lower()
            and "ftp" in (v.get("name") or "").lower()
            and v.get("status") == "CONFIRMED"
            for v in vulns
        )
        anon_ftp_potential = any(
            "anonymous" in (v.get("name") or "").lower()
            and "ftp" in (v.get("name") or "").lower()
            and v.get("status") == "POTENTIAL"
            for v in vulns
        )
        if anon_ftp_confirmed:
            ctrl._fail("Anonymous FTP login confirmed")
        elif anon_ftp_potential:
            ctrl.status = ControlStatus.FAIL
            ctrl.evidence.append(
                "Anonymous FTP login potential (unverified — manual confirmation needed)"
            )
        else:
            open_ports = self._results.get("open_ports") or []
            ftp_open = any(p.get("port") == 21 for p in open_ports)
            if ftp_open:
                ctrl._unknown(
                    "FTP port open but anonymous login check result is not available"
                )
            else:
                ctrl._pass("FTP port not open; anonymous login not applicable")
        return ctrl

    def _check_auth_002(self) -> ComplianceControl:
        """AUTH-002: Anonymous / unauthenticated service evidence from banners."""
        ctrl = ComplianceControl(
            control_id="AUTH-002",
            title="Unauthenticated Service Detected (Banner Evidence)",
            description=(
                "Banner data suggests at least one service may permit unauthenticated "
                "access (e.g., 'anonymous' keyword in banner, or service with no auth "
                "prompt observed)."
            ),
            rationale=(
                "Services that advertise or permit anonymous access increase the attack "
                "surface for data exfiltration and lateral movement."
            ),
            severity=ControlSeverity.MEDIUM,
        )
        open_ports = self._results.get("open_ports") or []
        flagged = []
        for p in open_ports:
            banner = (p.get("banner") or "").lower()
            if "anonymous" in banner or "no password" in banner:
                flagged.append(f"port {p.get('port')}/tcp")
        if flagged:
            ctrl._fail(f"Anonymous access hint in banner on: {', '.join(flagged)}")
        else:
            ctrl._pass("No anonymous-access hints detected in service banners")
        return ctrl

    # ------------------------------------------------------------------
    # OS lifecycle / patch posture (placeholder)
    # ------------------------------------------------------------------

    def _check_os_001(self) -> ComplianceControl:
        """OS-001: OS patch posture (placeholder — requires credentialed data)."""
        ctrl = ComplianceControl(
            control_id="OS-001",
            title="OS Patch Posture (Placeholder)",
            description=(
                "Evaluation of OS patch level and end-of-life status requires "
                "credentialed access to the target system. This control is a "
                "placeholder for future authenticated OS lifecycle checks."
            ),
            rationale=(
                "Running unsupported or unpatched operating systems significantly "
                "increases exposure to known vulnerabilities."
            ),
            severity=ControlSeverity.HIGH,
            requires_credentials=True,
        )
        if not self._has_creds:
            return ctrl._skip(
                "Credentialed access not available; OS patch posture cannot be evaluated"
            )
        auth_scan = self._results.get("auth_scan") or {}
        if not auth_scan.get("authenticated_mode"):
            return ctrl._skip(
                "No authentication probes succeeded; OS patch posture cannot be evaluated"
            )
        # When credentials are available and authentication succeeded, mark as
        # unknown — full OS patch evaluation is not yet implemented.
        return ctrl._unknown(
            "Credentialed access confirmed but OS patch posture evaluation is not yet "
            "implemented in this version (placeholder for future development)"
        )


# ---------------------------------------------------------------------------
# Compliance report
# ---------------------------------------------------------------------------

class ComplianceReport:
    """Aggregated result of running all controls for a profile."""

    def __init__(
        self,
        profile: str,
        target: str,
        controls: List[ComplianceControl],
    ) -> None:
        self.profile   = profile
        self.target    = target
        self.controls  = controls
        self.timestamp = datetime.now(timezone.utc).isoformat()

    # -- convenience accessors ----------------------------------------------

    @property
    def failed(self) -> List[ComplianceControl]:
        return [c for c in self.controls if c.status == ControlStatus.FAIL]

    @property
    def passed(self) -> List[ComplianceControl]:
        return [c for c in self.controls if c.status == ControlStatus.PASS]

    @property
    def skipped(self) -> List[ComplianceControl]:
        return [c for c in self.controls if c.status == ControlStatus.SKIP]

    @property
    def unknown(self) -> List[ComplianceControl]:
        return [c for c in self.controls if c.status == ControlStatus.UNKNOWN]

    def summary_counts(self) -> Dict[str, int]:
        return {
            "total":   len(self.controls),
            "pass":    len(self.passed),
            "fail":    len(self.failed),
            "unknown": len(self.unknown),
            "skip":    len(self.skipped),
        }

    def to_dict(self) -> Dict:
        counts = self.summary_counts()
        return {
            "profile":   self.profile,
            "target":    self.target,
            "timestamp": self.timestamp,
            "summary":   counts,
            "controls":  [c.to_dict() for c in self.controls],
            # Legacy compatibility: surface a top-level 'status' and 'issues'
            # so existing code that reads compliance['status'] keeps working.
            "status":    "FAIL" if counts["fail"] > 0 else "PASS",
            "issues":    [
                f"{c.control_id}: {c.title}" for c in self.failed
            ],
        }
