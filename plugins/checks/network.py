"""
Network / service vulnerability plugin checks.

Checks
------
BlueKeepCheck           CVE-2019-0708 — RDP exposure assessment.
FTPAnonCheck            FTP anonymous login probe.
TelnetBannerCheck       Telnet banner / cleartext exposure.
SNMPCommunityCheck      SNMP default community string probe.
DatabaseExposureCheck   Database port external exposure.
WebHeadersCheck         Missing HTTP security headers (requires *requests*).
"""

import socket
import struct
from typing import List

from .. import BaseCheck, CheckRegistry, Evidence, Finding

# Optional HTTP library (mirrors the pattern in vultron.py)
try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


# ---------------------------------------------------------------------------
# BlueKeep
# ---------------------------------------------------------------------------


@CheckRegistry.register
class BlueKeepCheck(BaseCheck):
    """CVE-2019-0708 (BlueKeep) — RDP exposure assessment.

    We can confirm RDP is exposed; OS-level patch status cannot be
    verified without credentials, so the finding is POTENTIAL.
    """

    check_id = "CVE-2019-0708"
    title = "BlueKeep — RDP exposed, patch status unverified"
    description = (
        "RDP is exposed on this host. CVE-2019-0708 (BlueKeep) affects "
        "unpatched Windows XP/2003/Vista/7/2008. Confirm the Windows build "
        "number to determine actual exposure."
    )
    category = "network"
    default_severity = "HIGH"
    required_ports = [3389]
    service_matchers = ["RDP"]

    def run(self, target: str, port: int = 3389, **kwargs) -> List[Finding]:
        return [Finding(
            id=self.check_id,
            title=self.title,
            description=self.description,
            status="POTENTIAL",
            severity="HIGH",
            confidence=0.5,
            target=target,
            port=port,
            service="RDP",
            evidence=Evidence(items=[f"RDP port {port}/tcp is open"]),
            cve_refs=["CVE-2019-0708"],
            cvss=9.8,
            remediation=(
                "Apply Windows security updates; "
                "enable Network Level Authentication."
            ),
            cisa_kev=True,
            exploit_available=True,
            name="BlueKeep (CVE-2019-0708)",
        )]


# ---------------------------------------------------------------------------
# FTP anonymous login
# ---------------------------------------------------------------------------


@CheckRegistry.register
class FTPAnonCheck(BaseCheck):
    """FTP anonymous login probe.

    Attempts to log in as ``anonymous`` / ``anonymous@example.com``.
    Returns CONFIRMED if login succeeds, POTENTIAL if the response is
    ambiguous, and INCONCLUSIVE on timeout or error.
    """

    check_id = "FTP-ANON"
    title = "FTP Anonymous Login Enabled"
    description = (
        "Tests whether the FTP server permits anonymous login. "
        "If successful, unauthenticated users may read or write files."
    )
    category = "service"
    default_severity = "HIGH"
    required_ports = [21]
    service_matchers = ["FTP", "FTP-DATA"]

    def run(self, target: str, port: int = 21, **kwargs) -> List[Finding]:
        evidence_items: List[str] = [f"FTP port {port}/tcp is open"]
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))

            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            if banner:
                evidence_items.append(f"FTP banner: {banner[:100]}")

            sock.send(b"USER anonymous\r\n")
            user_resp = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            if user_resp:
                evidence_items.append(f"USER response: {user_resp[:80]}")

            if user_resp.startswith("230"):
                sock.close()
                return [self._confirmed(target, port, evidence_items)]
            if user_resp.startswith(("4", "5")):
                sock.close()
                evidence_items.append("Anonymous login rejected at USER stage")
                return []

            sock.send(b"PASS anonymous@example.com\r\n")
            pass_resp = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            if pass_resp:
                evidence_items.append(f"PASS response: {pass_resp[:80]}")
            sock.close()

            if pass_resp.startswith("230"):
                return [self._confirmed(target, port, evidence_items)]
            if pass_resp.startswith(("3", "4", "5")):
                evidence_items.append("Anonymous login denied by server")
                return []
            # Ambiguous response
            return [Finding(
                id=f"FTP-ANON-{port}",
                title=f"FTP anonymous login result ambiguous on port {port}",
                description=f"FTP anonymous login result was ambiguous. Response: {pass_resp[:50]}",
                status="POTENTIAL",
                severity="MEDIUM",
                confidence=0.5,
                target=target,
                port=port,
                service="FTP",
                evidence=Evidence(items=evidence_items),
                remediation="Review FTP server configuration for anonymous access settings.",
                name="FTP Anonymous Login",
            )]

        except socket.timeout:
            evidence_items.append("Connection timed out during FTP anonymous login check")
            return [Finding(
                id=f"FTP-ANON-{port}",
                title=f"FTP anonymous login check inconclusive (timeout) on port {port}",
                description="FTP anonymous login check timed out. Manual verification required.",
                status="INCONCLUSIVE",
                severity="MEDIUM",
                confidence=0.2,
                target=target,
                port=port,
                service="FTP",
                evidence=Evidence(items=evidence_items),
                remediation="Verify FTP server anonymous access configuration manually.",
                name="FTP Anonymous Login",
            )]

        except Exception as exc:
            evidence_items.append(f"Check error: {exc}")
            return [Finding(
                id=f"FTP-ANON-{port}",
                title=f"FTP anonymous login check inconclusive (error) on port {port}",
                description=f"FTP anonymous login check could not complete: {exc}",
                status="INCONCLUSIVE",
                severity="MEDIUM",
                confidence=0.2,
                target=target,
                port=port,
                service="FTP",
                evidence=Evidence(items=evidence_items),
                remediation="Verify FTP server anonymous access configuration manually.",
                name="FTP Anonymous Login",
            )]

    @staticmethod
    def _confirmed(target: str, port: int, evidence_items: List[str]) -> Finding:
        return Finding(
            id=f"FTP-ANON-{port}",
            title=f"FTP anonymous login accepted on port {port}",
            description=(
                "The FTP server accepted anonymous login. "
                "Unauthenticated users may read or write files."
            ),
            status="CONFIRMED",
            severity="HIGH",
            confidence=0.9,
            target=target,
            port=port,
            service="FTP",
            evidence=Evidence(items=evidence_items),
            remediation="Disable anonymous FTP access unless explicitly required.",
            name="FTP Anonymous Login Enabled",
        )


# ---------------------------------------------------------------------------
# Telnet banner
# ---------------------------------------------------------------------------


@CheckRegistry.register
class TelnetBannerCheck(BaseCheck):
    """Telnet banner collection and cleartext exposure assessment.

    Any successful connection to a Telnet port is a POTENTIAL finding
    because the protocol transmits credentials in cleartext.
    """

    check_id = "TELNET-EXPOSURE"
    title = "Telnet Service Exposed"
    description = (
        "Telnet transmits all data, including credentials, in cleartext. "
        "Any network observer can intercept sessions."
    )
    category = "service"
    default_severity = "HIGH"
    required_ports = [23]
    service_matchers = ["Telnet"]

    def run(self, target: str, port: int = 23, **kwargs) -> List[Finding]:
        evidence_items: List[str] = [f"Telnet port {port}/tcp is open"]
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            raw = sock.recv(1024)
            sock.close()

            banner = raw.decode("utf-8", errors="ignore").strip()
            if banner:
                evidence_items.append(f"Telnet banner: {banner[:100]}")
            else:
                evidence_items.append("Connected but no banner text received")
            evidence_items.append(
                "Telnet transmits all data (including credentials) in plaintext"
            )

            return [Finding(
                id=f"TELNET-EXPOSURE-{port}",
                title=f"Telnet cleartext protocol exposed on port {port}",
                description=(
                    "Telnet is a legacy protocol that transmits all data, "
                    "including credentials, in cleartext. "
                    "Any network observer can intercept sessions."
                ),
                status="POTENTIAL",
                severity="HIGH",
                confidence=0.5,
                target=target,
                port=port,
                service="Telnet",
                evidence=Evidence(items=evidence_items),
                remediation="Disable Telnet; replace with SSH for encrypted remote access.",
                name="Telnet Service Exposed",
            )]

        except socket.timeout:
            evidence_items.append("Connection timed out during Telnet banner collection")
            return [Finding(
                id=f"TELNET-EXPOSURE-{port}",
                title=f"Telnet banner check inconclusive (timeout) on port {port}",
                description=(
                    "Telnet banner collection timed out. "
                    "The service may be running but unresponsive."
                ),
                status="INCONCLUSIVE",
                severity="MEDIUM",
                confidence=0.2,
                target=target,
                port=port,
                service="Telnet",
                evidence=Evidence(items=evidence_items),
                remediation="Disable Telnet; replace with SSH.",
                name="Telnet Service Exposed",
            )]

        except Exception as exc:
            evidence_items.append(f"Check error: {exc}")
            return [Finding(
                id=f"TELNET-EXPOSURE-{port}",
                title=f"Telnet banner check inconclusive (error) on port {port}",
                description=f"Telnet banner check could not complete: {exc}",
                status="INCONCLUSIVE",
                severity="MEDIUM",
                confidence=0.2,
                target=target,
                port=port,
                service="Telnet",
                evidence=Evidence(items=evidence_items),
                remediation="Disable Telnet; replace with SSH.",
                name="Telnet Service Exposed",
            )]


# ---------------------------------------------------------------------------
# SNMP default community
# ---------------------------------------------------------------------------


def _build_snmp_getrequest(community: str, request_id: int = 0x1234) -> bytes:
    """Build a minimal SNMP v1 GetRequest PDU for sysDescr.0 (read-only probe)."""
    oid_val = bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
    oid_tlv = bytes([0x06, len(oid_val)]) + oid_val
    null_tlv = bytes([0x05, 0x00])
    varbind_content = oid_tlv + null_tlv
    varbind = bytes([0x30, len(varbind_content)]) + varbind_content
    vbl = bytes([0x30, len(varbind)]) + varbind

    req_id_val = struct.pack(">I", request_id)
    req_id_tlv = bytes([0x02, len(req_id_val)]) + req_id_val
    err_status = bytes([0x02, 0x01, 0x00])
    err_index = bytes([0x02, 0x01, 0x00])
    pdu_content = req_id_tlv + err_status + err_index + vbl
    pdu = bytes([0xA0, len(pdu_content)]) + pdu_content

    version_tlv = bytes([0x02, 0x01, 0x00])
    comm_bytes = community.encode("ascii")
    comm_tlv = bytes([0x04, len(comm_bytes)]) + comm_bytes
    msg_content = version_tlv + comm_tlv + pdu
    return bytes([0x30, len(msg_content)]) + msg_content


@CheckRegistry.register
class SNMPCommunityCheck(BaseCheck):
    """SNMP default community string probe.

    Sends read-only SNMP GetRequest PDUs for community strings ``public``
    and ``private``.  Returns CONFIRMED if either is accepted,
    INCONCLUSIVE if all probes time out or error.
    """

    check_id = "SNMP-DEFAULT-COMMUNITY"
    title = "SNMP Default Community String"
    description = (
        "Tests whether the SNMP agent accepts default community strings "
        "('public', 'private').  Acceptance allows unauthenticated read "
        "access to device configuration and network topology."
    )
    category = "network"
    default_severity = "HIGH"
    required_ports = [161]
    service_matchers = ["SNMP"]

    _COMMUNITIES = ["public", "private"]

    def run(self, target: str, port: int = 161, **kwargs) -> List[Finding]:
        evidence_items: List[str] = [f"SNMP port {port} detected"]

        for community in self._COMMUNITIES:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                pkt = _build_snmp_getrequest(community)
                sock.sendto(pkt, (target, port))
                response, _ = sock.recvfrom(1024)
                sock.close()

                evidence_items.append(
                    f"SNMP community '{community}' accepted "
                    f"({len(response)} bytes received)"
                )
                return [Finding(
                    id=f"SNMP-DEFAULT-COMMUNITY-{port}",
                    title=f"SNMP default community '{community}' accepted on port {port}/udp",
                    description=(
                        f"The SNMP agent accepted the default community string '{community}'. "
                        "This allows unauthenticated read access to device configuration "
                        "and network topology information."
                    ),
                    status="CONFIRMED",
                    severity="HIGH",
                    confidence=0.9,
                    target=target,
                    port=port,
                    service="SNMP",
                    evidence=Evidence(items=evidence_items),
                    remediation=(
                        "Change SNMP community strings from defaults; "
                        "upgrade to SNMPv3 with authentication and encryption; "
                        "restrict SNMP access via firewall rules."
                    ),
                    name="SNMP Default Community String",
                )]

            except socket.timeout:
                evidence_items.append(f"SNMP community '{community}': no response (timeout)")
            except Exception as exc:
                evidence_items.append(f"SNMP community '{community}' check error: {exc}")

        # All probes inconclusive
        return [Finding(
            id=f"SNMP-DEFAULT-COMMUNITY-{port}",
            title=f"SNMP default community check inconclusive on port {port}/udp",
            description=(
                "SNMP default community probe received no response. "
                "The service may use non-default community strings or be filtered."
            ),
            status="INCONCLUSIVE",
            severity="MEDIUM",
            confidence=0.2,
            target=target,
            port=port,
            service="SNMP",
            evidence=Evidence(items=evidence_items),
            remediation=(
                "Use SNMPv3 with authentication and encryption; "
                "restrict SNMP access via firewall rules."
            ),
            name="SNMP Default Community String",
        )]


# ---------------------------------------------------------------------------
# Database exposure
# ---------------------------------------------------------------------------


@CheckRegistry.register
class DatabaseExposureCheck(BaseCheck):
    """Database port external exposure check.

    A database port that accepts a TCP connection from an external host is
    a CONFIRMED finding — it should not be publicly reachable.
    """

    check_id = "DB-EXPOSURE"
    title = "Database Port Externally Accessible"
    description = (
        "A database service is accessible from an external network. "
        "This significantly increases the attack surface."
    )
    category = "config"
    default_severity = "HIGH"
    required_ports = [1433, 3306, 5432, 6379, 27017]
    service_matchers = ["MySQL", "PostgreSQL", "MS-SQL", "MongoDB", "Redis"]

    def run(self, target: str, port: int = 3306, **kwargs) -> List[Finding]:
        service = kwargs.get("service", f"DB-{port}")
        return [Finding(
            id=f"DB-EXPOSURE-{port}",
            title=f"{service} database port {port} externally accessible",
            description=f"{service} is accessible from an external network on port {port}/tcp.",
            status="CONFIRMED",
            severity="HIGH",
            confidence=0.9,
            target=target,
            port=port,
            service=service,
            evidence=Evidence(items=[f"Port {port}/tcp ({service}) accepted TCP connection"]),
            remediation="Bind database to localhost only; restrict with firewall rules.",
            name=f"{service} Remote Access",
        )]


# ---------------------------------------------------------------------------
# Web security headers
# ---------------------------------------------------------------------------


@CheckRegistry.register
class WebHeadersCheck(BaseCheck):
    """Missing HTTP security headers check.

    Requires the *requests* library.  Skipped (empty result) when not available.
    """

    check_id = "WEB-HEADERS"
    title = "Missing HTTP Security Headers"
    description = (
        "Checks for the absence of recommended HTTP security response headers "
        "(X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, "
        "Content-Security-Policy)."
    )
    category = "config"
    default_severity = "MEDIUM"
    required_ports = [80, 443, 8080, 8443]
    service_matchers = ["HTTP", "HTTPS", "HTTP-Proxy", "HTTPS-Alt"]

    _REQUIRED_HEADERS = [
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "Content-Security-Policy",
    ]

    def run(self, target: str, port: int = 80, **kwargs) -> List[Finding]:
        if not _HAS_REQUESTS:
            return []

        protocol = "https" if port in (443, 8443) else "http"
        url = f"{protocol}://{target}:{port}"
        try:
            response = _requests.get(url, verify=False, timeout=5)
            headers = response.headers
            evidence_items = [f"HTTP {response.status_code} from {url}"]

            missing = [h for h in self._REQUIRED_HEADERS if h not in headers]
            if not missing:
                return []

            evidence_items.extend(f"Missing header: {h}" for h in missing)
            return [Finding(
                id=f"WEB-HEADERS-{port}",
                title=f"Missing HTTP security headers on port {port}",
                description=f"One or more security response headers are absent: {', '.join(missing)}",
                status="CONFIRMED",
                severity="MEDIUM",
                confidence=0.9,
                target=target,
                port=port,
                service="HTTP",
                evidence=Evidence(items=evidence_items),
                remediation=(
                    "Set X-Frame-Options, X-Content-Type-Options, "
                    "HSTS, and CSP headers."
                ),
                name="Missing Security Headers",
            )]

        except Exception:
            return []
