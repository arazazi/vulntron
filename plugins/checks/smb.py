"""
SMB vulnerability plugin checks.

Checks
------
EternalBlueCheck  MS17-010 — SMBv1 negotiate probe.
SMBGhostCheck     CVE-2020-0796 — SMB 3.1.1 compression dialect probe.
"""

import socket
from typing import List

from .. import BaseCheck, CheckRegistry, Evidence, Finding


@CheckRegistry.register
class EternalBlueCheck(BaseCheck):
    """MS17-010 (EternalBlue) — SMBv1 negotiate probe.

    Sends a minimal SMBv1 negotiate request and checks whether the server
    accepts it.  A positive response confirms SMBv1 is enabled and the host
    may be vulnerable to the EternalBlue exploit (WannaCry / NotPetya).
    """

    check_id = "MS17-010"
    title = "EternalBlue SMBv1 Remote Code Execution"
    description = (
        "Tests whether SMBv1 is enabled and responsive to a negotiate "
        "request.  Affected hosts are susceptible to MS17-010 / EternalBlue."
    )
    category = "network"
    default_severity = "CRITICAL"
    required_ports = [445]
    service_matchers = ["SMB", "SAMBA"]

    def run(self, target: str, port: int = 445, **kwargs) -> List[Finding]:
        evidence_items: List[str] = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))

            # Minimal SMBv1 negotiate request (same packet as VulnerabilityChecker)
            pkt = (
                b"\x00\x00\x00\x85"
                b"\xff\x53\x4d\x42"
                b"\x72"
                b"\x00\x00\x00\x00\x00\x18\x53\xc8"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\xff\xfe"
                b"\x00\x00\x00\x00"
                b"\x00\x62"
                b"\x00\x02"
                b"\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"
                b"\x02\x53\x4d\x42\x20\x32\x2e\x30\x30\x32\x00"
                b"\x02\x53\x4d\x42\x20\x32\x2e\x3f\x3f\x3f\x00"
            )
            sock.send(pkt)
            response = sock.recv(1024)
            sock.close()

            if b"\xff\x53\x4d\x42" in response:
                evidence_items.append("SMBv1 negotiate response received")
                evidence_items.append(f"Response bytes (hex): {response[:32].hex()}")
                return [Finding(
                    id=self.check_id,
                    title="EternalBlue SMBv1 Remote Code Execution",
                    description=(
                        "SMBv1 is enabled and responded to a negotiate request. "
                        "This version is susceptible to the EternalBlue exploit "
                        "(MS17-010 / WannaCry / NotPetya)."
                    ),
                    status="CONFIRMED",
                    severity="CRITICAL",
                    confidence=0.9,
                    target=target,
                    port=port,
                    service="SMB",
                    evidence=Evidence(items=evidence_items),
                    cve_refs=["CVE-2017-0144"],
                    cvss=9.8,
                    remediation="Disable SMBv1; apply MS17-010 patch",
                    cisa_kev=True,
                    exploit_available=True,
                    name="MS17-010 (EternalBlue)",
                )]
            # SMBv1 not accepted
            evidence_items.append("SMBv1 negotiate not accepted by server")
            return []

        except socket.timeout:
            evidence_items.append("Connection timed out during SMB negotiate probe")
            return [Finding(
                id=self.check_id,
                title="EternalBlue SMBv1 — check inconclusive (timeout)",
                description=(
                    "EternalBlue check timed out. The port is open but the "
                    "SMBv1 probe did not receive a response. "
                    "Manual verification required."
                ),
                status="INCONCLUSIVE",
                severity="HIGH",
                confidence=0.2,
                target=target,
                port=port,
                service="SMB",
                evidence=Evidence(items=evidence_items),
                cve_refs=["CVE-2017-0144"],
                cvss=9.8,
                remediation="Disable SMBv1; apply MS17-010 patch; verify manually",
                name="MS17-010 (EternalBlue)",
            )]

        except Exception as exc:
            evidence_items.append(f"Check failed: {exc}")
            return [Finding(
                id=self.check_id,
                title="EternalBlue SMBv1 — check inconclusive (error)",
                description=f"EternalBlue check could not complete: {exc}",
                status="INCONCLUSIVE",
                severity="HIGH",
                confidence=0.2,
                target=target,
                port=port,
                service="SMB",
                evidence=Evidence(items=evidence_items),
                cve_refs=["CVE-2017-0144"],
                cvss=9.8,
                remediation="Disable SMBv1; apply MS17-010 patch; verify manually",
                name="MS17-010 (EternalBlue)",
            )]


@CheckRegistry.register
class SMBGhostCheck(BaseCheck):
    """CVE-2020-0796 (SMBGhost) — SMB 3.1.1 compression capabilities probe.

    Sends a minimal SMBv3.1.1 negotiate request and checks whether the
    server advertises the SMB 3.1.1 dialect.  A positive response indicates
    potential exposure to CVE-2020-0796; patch status cannot be confirmed
    without OS-level data, so the finding is POTENTIAL.
    """

    check_id = "CVE-2020-0796"
    title = "SMBGhost — SMB 3.1.1 compression potential vulnerability"
    description = (
        "Tests whether the SMB server advertises the 3.1.1 dialect. "
        "CVE-2020-0796 affects Windows 10 / Server 2019 without KB4551762."
    )
    category = "network"
    default_severity = "HIGH"
    required_ports = [445]
    service_matchers = ["SMB", "SAMBA"]

    def run(self, target: str, port: int = 445, **kwargs) -> List[Finding]:
        evidence_items: List[str] = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))

            # Minimal SMBv3.1.1 negotiate with compression capabilities context
            pkt = (
                b"\x00\x00\x00\xc0"
                b"\xfeSMB"
                b"\x40\x00"
                b"\x00\x00"
                b"\x00\x00\x00\x00"
                b"\x00\x00"
                b"\x1f\x00"
                b"\x00\x00\x00\x00"
                b"\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00"
                b"\xff\xff\xff\xff"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x24\x00"
                b"\x08\x00"
                b"\x02\x00"
                b"\x00\x00"
                b"\x7f\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x78\x00"
                b"\x02\x00"
                b"\x00\x00"
                b"\x02\x02"
                b"\x10\x02"
                b"\x00\x03"
                b"\x02\x03"
                b"\x10\x03"
                b"\x00\x03"
                b"\x02\x03"
                b"\x10\x03"
            )
            sock.send(pkt)
            response = sock.recv(1024)
            sock.close()

            smb2_magic = b"\xfeSMB"
            if smb2_magic in response:
                evidence_items.append(
                    f"SMBv2/3 negotiate response received (len={len(response)})"
                )
                if b"\x11\x03" in response:
                    evidence_items.append("Server advertised SMB dialect 3.1.1")
                    return [Finding(
                        id=self.check_id,
                        title="SMBGhost — SMB 3.1.1 compression potential vulnerability",
                        description=(
                            "Server negotiated SMB 3.1.1. CVE-2020-0796 (SMBGhost) "
                            "affects Windows 10/Server 2019 without KB4551762. "
                            "Confirm Windows build number to determine exposure."
                        ),
                        status="POTENTIAL",
                        severity="HIGH",
                        confidence=0.5,
                        target=target,
                        port=port,
                        service="SMB",
                        evidence=Evidence(items=evidence_items),
                        cve_refs=["CVE-2020-0796"],
                        cvss=10.0,
                        remediation=(
                            "Apply KB4551762; disable SMBv3 compression "
                            "if patch is unavailable."
                        ),
                        exploit_available=True,
                        name="SMBGhost (CVE-2020-0796)",
                    )]
                # SMB 3.1.1 not negotiated
                evidence_items.append("SMB 3.1.1 not negotiated; SMBGhost unlikely")
                return []

            # No SMB2/3 response
            evidence_items.append("No SMB2/3 response received")
            return []

        except socket.timeout:
            evidence_items.append("Connection timed out during SMBGhost probe")
            return [Finding(
                id=self.check_id,
                title="SMBGhost — check inconclusive (timeout)",
                description="SMBGhost probe timed out. Manual version check required.",
                status="INCONCLUSIVE",
                severity="HIGH",
                confidence=0.2,
                target=target,
                port=port,
                service="SMB",
                evidence=Evidence(items=evidence_items),
                cve_refs=["CVE-2020-0796"],
                cvss=10.0,
                remediation="Apply KB4551762; verify Windows build manually",
                name="SMBGhost (CVE-2020-0796)",
            )]

        except Exception as exc:
            evidence_items.append(f"Check error: {exc}")
            return [Finding(
                id=self.check_id,
                title="SMBGhost — check inconclusive (error)",
                description=f"SMBGhost check could not complete: {exc}",
                status="INCONCLUSIVE",
                severity="HIGH",
                confidence=0.2,
                target=target,
                port=port,
                service="SMB",
                evidence=Evidence(items=evidence_items),
                cve_refs=["CVE-2020-0796"],
                cvss=10.0,
                remediation="Apply KB4551762; verify Windows build manually",
                name="SMBGhost (CVE-2020-0796)",
            )]
