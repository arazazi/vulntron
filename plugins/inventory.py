"""
Asset inventory core + host profiling for Vultron PR4.

This module provides a first-class asset inventory subsystem that consolidates
host/service/context data produced by all scan modules (TCP, UDP, TLS, vuln
checks) into stable, normalised asset records suitable for reporting, tracking,
and future compliance/patch workflows.

Public API
----------
AssetRecord             Normalised record for a single discovered asset.
ServiceRecord           Normalised per-port/protocol service record.
TLSServiceRecord        TLS posture snapshot for a TLS-capable port.
OsHint                  OS/platform hint with source and confidence.
InventorySnapshot       Collection of asset records with snapshot metadata.
InventoryBuilder        Builds/merges a snapshot from HybridScanner results.
HostProfiler            Derives role, risk, and exposure posture fields.
persist_inventory       Serialise a snapshot to a JSON file.
"""

import hashlib
import json
import os
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Role-hint heuristics
# ---------------------------------------------------------------------------

#: (port_set, role_label) ordered from most-specific to least-specific.
#: The first matching rule wins.
_ROLE_PORT_MAP: List[Tuple[frozenset, str]] = [
    (frozenset({25, 465, 587, 110, 143, 993, 995}), "mail-server"),
    (frozenset({53}),                               "dns-server"),
    (frozenset({1433, 1521, 3306, 5432, 27017}),    "database-server"),
    (frozenset({161, 162}),                         "network-device"),
    (frozenset({80, 443, 8080, 8443}),              "web-server"),
    (frozenset({445, 139}),                         "file-server"),
    (frozenset({3389}),                             "workstation"),
    (frozenset({23}),                               "legacy-device"),
    (frozenset({22}),                               "server"),
]


def _derive_role(tcp_ports: List[int], udp_ports: List[int]) -> str:
    """Return a role label for the given open port sets, or 'unknown'."""
    all_ports = set(tcp_ports) | set(udp_ports)
    for port_set, label in _ROLE_PORT_MAP:
        if all_ports & port_set:
            return label
    return "unknown"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class OsHint:
    """OS / platform hint with provenance and confidence.

    Attributes
    ----------
    hint:       Human-readable OS / platform description.
    source:     Which scan module produced this hint (e.g. ``banner``, ``tls``).
    confidence: Float 0.0–1.0; higher means more reliable.
    """

    hint: str
    source: str
    confidence: float = 0.5

    def to_dict(self) -> Dict[str, Any]:
        return {"hint": self.hint, "source": self.source, "confidence": self.confidence}


@dataclass
class TLSServiceRecord:
    """Minimal TLS posture snapshot for one TLS-capable port.

    Attributes
    ----------
    port:               TCP port number.
    protocol_version:   Negotiated TLS version string (e.g. ``TLSv1.2``).
    cipher_name:        Negotiated cipher suite name.
    cert_cn:            Certificate Subject CN, or ``None``.
    cert_issuer:        Certificate Issuer CN, or ``None``.
    cert_expires:       Certificate expiry ISO-8601 string, or ``None``.
    cert_self_signed:   Whether the certificate is self-signed.
    has_forward_secrecy: Whether the cipher provides forward secrecy.
    error:              TLS handshake error message, or ``None``.
    """

    port: int
    protocol_version: Optional[str] = None
    cipher_name: Optional[str] = None
    cert_cn: Optional[str] = None
    cert_issuer: Optional[str] = None
    cert_expires: Optional[str] = None
    cert_self_signed: bool = False
    has_forward_secrecy: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "protocol_version": self.protocol_version,
            "cipher_name": self.cipher_name,
            "cert_cn": self.cert_cn,
            "cert_issuer": self.cert_issuer,
            "cert_expires": self.cert_expires,
            "cert_self_signed": self.cert_self_signed,
            "has_forward_secrecy": self.has_forward_secrecy,
            "error": self.error,
        }


@dataclass
class ServiceRecord:
    """Normalised per-port/protocol service entry.

    Attributes
    ----------
    port:       Port number.
    protocol:   ``tcp`` or ``udp``.
    service:    Guessed service name (e.g. ``http``, ``ssh``), or ``None``.
    banner:     Raw banner snippet, or ``None``.
    state:      Port state string (``open``, ``open|filtered``).
    version:    Version hint from fingerprint, or ``None``.
    tls:        Associated :class:`TLSServiceRecord`, or ``None``.
    """

    port: int
    protocol: str = "tcp"
    service: Optional[str] = None
    banner: Optional[str] = None
    state: str = "open"
    version: Optional[str] = None
    tls: Optional[TLSServiceRecord] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "banner": self.banner,
            "state": self.state,
            "version": self.version,
        }
        if self.tls is not None:
            d["tls"] = self.tls.to_dict()
        return d


@dataclass
class AssetRecord:
    """Normalised record for a single discovered asset.

    This is the stable, canonical representation of an asset after all scan
    modules have been merged.  Fields are additive: merging a second scan
    result enriches the record without overwriting existing data.

    Attributes
    ----------
    asset_id:       Deterministic fingerprint (SHA-256 hex of canonical key).
    ip:             Primary IP address, or ``None`` if unresolvable.
    hostname:       Reverse/forward-resolved hostname/FQDN, or ``None``.
    os_hints:       List of OS / platform hints with provenance.
    tcp_services:   Open TCP services keyed by port.
    udp_services:   Open UDP services keyed by port.
    first_seen:     ISO-8601 timestamp of first observation.
    last_seen:      ISO-8601 timestamp of most recent observation.
    scan_sources:   List of scan-module identifiers that contributed data.
    vuln_summary:   Aggregated vulnerability counter dict.
    risk_level:     Derived risk level: ``critical``, ``high``, ``medium``,
                    ``low``, or ``none``.
    role:           Inferred host role label (see :func:`_derive_role`).
    role_evidence:  Ports/signals that led to the role inference.
    exposure_summary: Plain-text exposure summary string.

    Cloud metadata fields (populated by cloud enrichment phase, PR7)
    ----------------------------------------------------------------
    cloud_provider:           Cloud provider label (e.g. ``'aws'``), or ``None``.
    cloud_instance_id:        Provider instance identifier (e.g. ``i-0abc1234``).
    cloud_region:             Provider region (e.g. ``us-east-1``), or ``None``.
    cloud_instance_state:     Instance lifecycle state (e.g. ``running``).
    cloud_instance_type:      Machine type (e.g. ``t3.micro``), or ``None``.
    cloud_tags:               Key/value tag dict attached to the instance.
    cloud_vpc_id:             VPC identifier, or ``None``.
    cloud_subnet_id:          Subnet identifier, or ``None``.
    cloud_security_group_ids: List of security group identifiers.
    """

    asset_id: str
    ip: Optional[str] = None
    hostname: Optional[str] = None
    os_hints: List[OsHint] = field(default_factory=list)
    tcp_services: Dict[int, ServiceRecord] = field(default_factory=dict)
    udp_services: Dict[int, ServiceRecord] = field(default_factory=dict)
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    scan_sources: List[str] = field(default_factory=list)
    vuln_summary: Dict[str, int] = field(default_factory=dict)
    risk_level: str = "none"
    role: str = "unknown"
    role_evidence: List[str] = field(default_factory=list)
    exposure_summary: str = ""
    # Cloud metadata (PR7) — all optional, populated by CloudCorrelator
    cloud_provider: Optional[str] = None
    cloud_instance_id: Optional[str] = None
    cloud_region: Optional[str] = None
    cloud_instance_state: Optional[str] = None
    cloud_instance_type: Optional[str] = None
    cloud_tags: Dict[str, str] = field(default_factory=dict)
    cloud_vpc_id: Optional[str] = None
    cloud_subnet_id: Optional[str] = None
    cloud_security_group_ids: List[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Merge helpers
    # ------------------------------------------------------------------

    def merge_tcp_service(self, rec: ServiceRecord) -> None:
        """Add or enrich a TCP service record (non-destructive merge)."""
        port = rec.port
        if port not in self.tcp_services:
            self.tcp_services[port] = rec
        else:
            existing = self.tcp_services[port]
            # Enrich existing record with any new non-None fields
            if rec.service and not existing.service:
                existing.service = rec.service
            if rec.banner and not existing.banner:
                existing.banner = rec.banner
            if rec.version and not existing.version:
                existing.version = rec.version
            if rec.tls and not existing.tls:
                existing.tls = rec.tls

    def merge_udp_service(self, rec: ServiceRecord) -> None:
        """Add or enrich a UDP service record (non-destructive merge)."""
        port = rec.port
        if port not in self.udp_services:
            self.udp_services[port] = rec
        else:
            existing = self.udp_services[port]
            if rec.service and not existing.service:
                existing.service = rec.service
            if rec.banner and not existing.banner:
                existing.banner = rec.banner
            if rec.version and not existing.version:
                existing.version = rec.version

    def add_source(self, source: str) -> None:
        """Record that ``source`` contributed data to this asset."""
        if source not in self.scan_sources:
            self.scan_sources.append(source)

    def add_os_hint(self, hint: OsHint) -> None:
        """Append an OS hint, deduplicating by (hint, source)."""
        for existing in self.os_hints:
            if existing.hint == hint.hint and existing.source == hint.source:
                return
        self.os_hints.append(hint)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dict suitable for JSON output."""
        return {
            "asset_id": self.asset_id,
            "ip": self.ip,
            "hostname": self.hostname,
            "os_hints": [h.to_dict() for h in self.os_hints],
            "tcp_services": {
                str(p): s.to_dict() for p, s in sorted(self.tcp_services.items())
            },
            "udp_services": {
                str(p): s.to_dict() for p, s in sorted(self.udp_services.items())
            },
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "scan_sources": list(self.scan_sources),
            "vuln_summary": dict(self.vuln_summary),
            "risk_level": self.risk_level,
            "role": self.role,
            "role_evidence": list(self.role_evidence),
            "exposure_summary": self.exposure_summary,
            # Cloud metadata (PR7)
            "cloud_provider": self.cloud_provider,
            "cloud_instance_id": self.cloud_instance_id,
            "cloud_region": self.cloud_region,
            "cloud_instance_state": self.cloud_instance_state,
            "cloud_instance_type": self.cloud_instance_type,
            "cloud_tags": dict(self.cloud_tags),
            "cloud_vpc_id": self.cloud_vpc_id,
            "cloud_subnet_id": self.cloud_subnet_id,
            "cloud_security_group_ids": list(self.cloud_security_group_ids),
        }


@dataclass
class InventorySnapshot:
    """Collection of asset records produced by one or more scan runs.

    Attributes
    ----------
    snapshot_id:    Unique identifier (derived from timestamp + target count).
    generated_at:   ISO-8601 generation timestamp.
    asset_count:    Total number of distinct assets recorded.
    assets:         List of :class:`AssetRecord` objects.
    schema_version: Snapshot schema version for future compatibility.
    """

    snapshot_id: str
    generated_at: str
    assets: List[AssetRecord] = field(default_factory=list)
    schema_version: str = "1.0"

    @property
    def asset_count(self) -> int:
        return len(self.assets)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "asset_count": self.asset_count,
            "assets": [a.to_dict() for a in self.assets],
        }


# ---------------------------------------------------------------------------
# Asset identity
# ---------------------------------------------------------------------------


def _make_asset_id(ip: Optional[str], hostname: Optional[str]) -> str:
    """Derive a stable, deterministic asset fingerprint.

    The fingerprint is the first 16 hex chars of the SHA-256 hash of the
    canonical key ``<ip>|<hostname>`` (using empty string for absent fields).
    This guarantees stability across repeated scans of the same target.
    """
    canonical = f"{ip or ''}|{hostname or ''}".lower()
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def _resolve_ip(target: str) -> Tuple[Optional[str], Optional[str]]:
    """Return ``(ip, hostname)`` for *target*.

    If *target* looks like an IP address, resolve hostname via rDNS
    (best-effort; ``None`` on failure).  If *target* looks like a hostname,
    resolve to IP (best-effort; fall back to ``None``).
    """
    # Determine if target is already an IP address
    try:
        socket.inet_pton(socket.AF_INET, target)
        # It's an IPv4 address
        ip = target
        try:
            hostname = socket.gethostbyaddr(target)[0]
        except Exception:
            hostname = None
        return ip, hostname
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, target)
        # It's an IPv6 address
        ip = target
        try:
            hostname = socket.gethostbyaddr(target)[0]
        except Exception:
            hostname = None
        return ip, hostname
    except OSError:
        pass

    # It's a hostname — resolve to IP
    hostname = target
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        ip = None
    return ip, hostname


# ---------------------------------------------------------------------------
# InventoryBuilder
# ---------------------------------------------------------------------------


class InventoryBuilder:
    """Builds an :class:`InventorySnapshot` from HybridScanner ``results``.

    This class merges observations from all scan modules (TCP, UDP, TLS,
    vulnerability checks, auth scan) into a single normalised
    :class:`AssetRecord` per host.

    Usage::

        builder = InventoryBuilder()
        snapshot = builder.build(scanner.results)
    """

    def build(self, results: Dict[str, Any]) -> InventorySnapshot:
        """Build a snapshot from a completed scan's results dict.

        Parameters
        ----------
        results:
            The ``HybridScanner.results`` dict produced after a full scan run.

        Returns
        -------
        InventorySnapshot
            A snapshot containing one :class:`AssetRecord` (the scanned host).
        """
        now = datetime.now(timezone.utc).isoformat()
        target: str = results.get("target", "")

        # Resolve network identity
        ip, hostname = _resolve_ip(target)
        asset_id = _make_asset_id(ip, hostname)

        asset = AssetRecord(
            asset_id=asset_id,
            ip=ip,
            hostname=hostname,
            first_seen=results.get("timestamp", now),
            last_seen=now,
        )

        # --- TCP services ---------------------------------------------------
        for port_info in results.get("open_ports", []):
            port = port_info.get("port")
            if port is None:
                continue
            rec = ServiceRecord(
                port=port,
                protocol="tcp",
                service=port_info.get("service"),
                banner=port_info.get("banner") or None,
                state="open",
                version=port_info.get("version") or None,
            )
            asset.merge_tcp_service(rec)
            asset.add_source("tcp-scan")

        # --- UDP services ---------------------------------------------------
        for port_info in results.get("udp_ports", []):
            port = port_info.get("port")
            if port is None:
                continue
            rec = ServiceRecord(
                port=port,
                protocol="udp",
                service=port_info.get("service"),
                banner=port_info.get("banner") or None,
                state=port_info.get("state", "open"),
                version=port_info.get("version") or None,
            )
            asset.merge_udp_service(rec)
            asset.add_source("udp-scan")

        # --- TLS inspection -------------------------------------------------
        for port_str, tls_data in results.get("tls_scan", {}).items():
            try:
                port = int(port_str)
            except (ValueError, TypeError):
                continue
            tls_rec = TLSServiceRecord(
                port=port,
                protocol_version=tls_data.get("protocol_version"),
                cipher_name=tls_data.get("cipher_name"),
                error=tls_data.get("error"),
                has_forward_secrecy=bool(tls_data.get("has_forward_secrecy", False)),
            )
            # Extract cert info if present
            cert = tls_data.get("cert_info") or {}
            if isinstance(cert, dict):
                tls_rec.cert_cn = cert.get("subject_cn")
                tls_rec.cert_issuer = cert.get("issuer_cn")
                tls_rec.cert_expires = cert.get("not_after")
                tls_rec.cert_self_signed = bool(cert.get("is_self_signed", False))

            # Attach TLS record to the TCP service (create stub if needed)
            if port in asset.tcp_services:
                asset.tcp_services[port].tls = tls_rec
            else:
                stub = ServiceRecord(port=port, protocol="tcp", state="open", tls=tls_rec)
                asset.tcp_services[port] = stub
            asset.add_source("tls-inspect")

        # --- Vulnerability summary ------------------------------------------
        vulns = results.get("vulnerabilities", [])
        asset.vuln_summary = self._summarise_vulns(vulns)

        # --- OS hints from banners / TLS certs ------------------------------
        for svc in asset.tcp_services.values():
            if svc.banner:
                hint = _os_hint_from_banner(svc.banner)
                if hint:
                    asset.add_os_hint(OsHint(hint=hint, source="banner", confidence=0.4))
            if svc.tls and svc.tls.cert_cn:
                # TLS CN is occasionally platform-indicative (e.g. synology/mikrotik)
                pass  # placeholder for future enrichment

        snapshot_id = hashlib.sha256(
            f"{now}{target}".encode()
        ).hexdigest()[:12]

        snapshot = InventorySnapshot(
            snapshot_id=snapshot_id,
            generated_at=now,
            assets=[asset],
        )
        return snapshot

    # ------------------------------------------------------------------

    @staticmethod
    def _summarise_vulns(vulns: List[Dict[str, Any]]) -> Dict[str, int]:
        """Return aggregated vulnerability counters for the asset."""
        return {
            "total": len(vulns),
            "critical_confirmed": sum(
                1 for v in vulns
                if v.get("severity") == "CRITICAL" and v.get("status") == "CONFIRMED"
            ),
            "high_confirmed": sum(
                1 for v in vulns
                if v.get("severity") == "HIGH" and v.get("status") == "CONFIRMED"
            ),
            "medium_confirmed": sum(
                1 for v in vulns
                if v.get("severity") == "MEDIUM" and v.get("status") == "CONFIRMED"
            ),
            "potential": sum(1 for v in vulns if v.get("status") == "POTENTIAL"),
            "inconclusive": sum(1 for v in vulns if v.get("status") == "INCONCLUSIVE"),
            "kev_confirmed": sum(
                1 for v in vulns
                if v.get("cisa_kev") and v.get("status") == "CONFIRMED"
            ),
        }


# ---------------------------------------------------------------------------
# Simple OS banner heuristics
# ---------------------------------------------------------------------------

_OS_BANNER_HINTS: List[Tuple[str, str]] = [
    ("windows", "Windows"),
    ("linux",   "Linux"),
    ("ubuntu",  "Ubuntu Linux"),
    ("debian",  "Debian Linux"),
    ("centos",  "CentOS Linux"),
    ("fedora",  "Fedora Linux"),
    ("freebsd", "FreeBSD"),
    ("openbsd", "OpenBSD"),
    ("cisco",   "Cisco IOS"),
    ("juniper", "Juniper JunOS"),
    ("mikrotik","MikroTik RouterOS"),
    ("synology","Synology DSM"),
    ("openssh", "SSH server (OpenSSH)"),
    ("microsoft", "Windows / Microsoft"),
]


def _os_hint_from_banner(banner: str) -> Optional[str]:
    """Extract a coarse OS hint from a service banner string, or ``None``."""
    lower = banner.lower()
    for keyword, label in _OS_BANNER_HINTS:
        if keyword in lower:
            return label
    return None


# ---------------------------------------------------------------------------
# HostProfiler
# ---------------------------------------------------------------------------


class HostProfiler:
    """Derives role, risk level, and exposure summary for an :class:`AssetRecord`.

    Profiling is heuristic and explainable: all evidence used to derive
    role/risk is recorded in the asset record so it can be audited.

    Usage::

        profiler = HostProfiler()
        profiler.profile(asset)   # enriches asset in-place
    """

    def profile(self, asset: AssetRecord) -> None:
        """Enrich *asset* with role, risk level, and exposure summary.

        All modifications are made in-place.
        """
        tcp_ports = sorted(asset.tcp_services.keys())
        udp_ports = sorted(asset.udp_services.keys())

        # --- Role inference ------------------------------------------------
        asset.role = _derive_role(tcp_ports, udp_ports)
        asset.role_evidence = self._build_role_evidence(asset.role, tcp_ports, udp_ports)

        # --- Risk level ----------------------------------------------------
        asset.risk_level = self._derive_risk(asset.vuln_summary)

        # --- Exposure summary -----------------------------------------------
        asset.exposure_summary = self._build_exposure_summary(
            tcp_ports, udp_ports, asset
        )

    # ------------------------------------------------------------------

    @staticmethod
    def _build_role_evidence(
        role: str, tcp_ports: List[int], udp_ports: List[int]
    ) -> List[str]:
        """Return a list of evidence strings that justify the role label."""
        evidence: List[str] = []
        all_ports = set(tcp_ports) | set(udp_ports)
        for port_set, label in _ROLE_PORT_MAP:
            matched = all_ports & port_set
            if matched and label == role:
                for p in sorted(matched):
                    proto = "tcp" if p in set(tcp_ports) else "udp"
                    evidence.append(f"port {p}/{proto} open → {label}")
        if not evidence and role == "unknown":
            evidence.append("no recognisable service ports; role undetermined")
        return evidence

    @staticmethod
    def _derive_risk(vuln_summary: Dict[str, int]) -> str:
        """Derive a single risk level label from the vulnerability summary."""
        if vuln_summary.get("critical_confirmed", 0) > 0:
            return "critical"
        if vuln_summary.get("high_confirmed", 0) > 0:
            return "high"
        if vuln_summary.get("medium_confirmed", 0) > 0:
            return "medium"
        if vuln_summary.get("potential", 0) > 0 or vuln_summary.get("inconclusive", 0) > 0:
            return "low"
        return "none"

    @staticmethod
    def _build_exposure_summary(
        tcp_ports: List[int],
        udp_ports: List[int],
        asset: AssetRecord,
    ) -> str:
        """Build a concise one-line exposure summary."""
        parts: List[str] = []
        if tcp_ports:
            parts.append(f"{len(tcp_ports)} TCP port(s) open")
        if udp_ports:
            parts.append(f"{len(udp_ports)} UDP port(s) open/filtered")
        tls_ports = [
            p for p, svc in asset.tcp_services.items()
            if svc.tls is not None and not svc.tls.error
        ]
        if tls_ports:
            parts.append(f"{len(tls_ports)} TLS-capable port(s)")
        if not parts:
            parts.append("no open ports detected")
        return "; ".join(parts)


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def persist_inventory(snapshot: InventorySnapshot, output_path: str) -> None:
    """Serialise *snapshot* to a JSON file at *output_path*.

    Parent directories are created automatically.  The file is written with
    pretty-printed JSON (indent=2) for human readability and diffability.

    Parameters
    ----------
    snapshot:
        The :class:`InventorySnapshot` to persist.
    output_path:
        Absolute or relative path to the output ``.json`` file.

    Raises
    ------
    OSError
        If the file cannot be written (permissions, disk-full, etc.).
    """
    dir_path = os.path.dirname(output_path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(snapshot.to_dict(), fh, indent=2)
