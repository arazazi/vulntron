"""
Authenticated connectivity probe checks (PR1).

These checks declare that they support credentialed scanning and
produce informational findings about authenticated session capability.

Checks
------
SSHConnectivityCheck
    SSH port reachability and optional authenticated session verification.
WinRMConnectivityCheck
    WinRM port reachability and optional authenticated session verification.
WMIConnectivityCheck
    WMI/DCOM port reachability and optional authenticated session verification.
"""

from typing import List, Optional

from .. import BaseCheck, CheckRegistry, Evidence, Finding
from ..auth_executor import (
    AuthenticatedExecutor,
    _probe_ssh,
    _probe_winrm,
    _probe_wmi,
)
from ..credentials import CredentialSet


# ---------------------------------------------------------------------------
# SSH connectivity probe
# ---------------------------------------------------------------------------


@CheckRegistry.register
class SSHConnectivityCheck(BaseCheck):
    """SSH connectivity and authentication capability probe.

    For unauthenticated scans (no SSH credential configured) confirms
    TCP reachability only.  With credentials, also verifies authentication.
    Gracefully skips (empty list) when the port is not open.
    """

    check_id = "AUTH-PROBE-SSH"
    title = "SSH Authenticated Connectivity Probe"
    description = (
        "Verifies SSH port reachability and, when SSH credentials are "
        "configured, confirms authentication capability.  This is a "
        "non-invasive informational probe — no changes are made."
    )
    category = "network"
    default_severity = "INFO"
    required_ports = [22]
    service_matchers = ["SSH"]

    #: This check can use credentials but does not require them.
    requires_credentials: bool = False
    credential_types: List[str] = ["ssh"]

    def run(
        self,
        target: str,
        port: int = 22,
        credential_set: Optional[CredentialSet] = None,
        **kwargs,
    ) -> List[Finding]:
        creds = credential_set or CredentialSet()
        # Use the same port that was discovered (may differ from default 22)
        if creds.ssh is not None:
            creds.ssh.port = port
        result = _probe_ssh(target, creds)
        if not result.success and result.error and "not reachable" in result.message:
            return []  # Port closed/filtered — skip silently

        status = "CONFIRMED" if result.success else "INCONCLUSIVE"
        confidence = 0.9 if result.success else 0.2
        evidence_items = [result.message]
        if result.error:
            evidence_items.append(f"Note: {result.error}")

        return [Finding(
            id=self.check_id,
            title=self.title,
            description=self.description,
            status=status,
            severity="INFO",
            confidence=confidence,
            target=target,
            port=port,
            service="SSH",
            evidence=Evidence(items=evidence_items),
            name=self.title,
        )]


# ---------------------------------------------------------------------------
# WinRM connectivity probe
# ---------------------------------------------------------------------------


@CheckRegistry.register
class WinRMConnectivityCheck(BaseCheck):
    """WinRM connectivity and authentication capability probe.

    For unauthenticated scans confirms TCP reachability only.  With
    WinRM credentials, also verifies session authentication.
    """

    check_id = "AUTH-PROBE-WINRM"
    title = "WinRM Authenticated Connectivity Probe"
    description = (
        "Verifies WinRM port reachability and, when WinRM credentials are "
        "configured, confirms authentication capability.  This is a "
        "non-invasive informational probe — no changes are made."
    )
    category = "network"
    default_severity = "INFO"
    required_ports = [5985, 5986]
    service_matchers = ["WinRM-HTTP", "WinRM-HTTPS"]

    requires_credentials: bool = False
    credential_types: List[str] = ["winrm"]

    def run(
        self,
        target: str,
        port: int = 5985,
        credential_set: Optional[CredentialSet] = None,
        **kwargs,
    ) -> List[Finding]:
        creds = credential_set or CredentialSet()
        if creds.winrm is not None:
            creds.winrm.port = port
        result = _probe_winrm(target, creds)
        if not result.success and "not reachable" in result.message:
            return []

        status = "CONFIRMED" if result.success else "INCONCLUSIVE"
        confidence = 0.9 if result.success else 0.2
        evidence_items = [result.message]
        if result.error:
            evidence_items.append(f"Note: {result.error}")

        return [Finding(
            id=self.check_id,
            title=self.title,
            description=self.description,
            status=status,
            severity="INFO",
            confidence=confidence,
            target=target,
            port=port,
            service="WinRM",
            evidence=Evidence(items=evidence_items),
            name=self.title,
        )]


# ---------------------------------------------------------------------------
# WMI connectivity probe
# ---------------------------------------------------------------------------


@CheckRegistry.register
class WMIConnectivityCheck(BaseCheck):
    """WMI/DCOM connectivity and authentication capability probe.

    For unauthenticated scans confirms DCOM port 135/tcp reachability only.
    With WMI credentials, also verifies WMI namespace access.
    """

    check_id = "AUTH-PROBE-WMI"
    title = "WMI Authenticated Connectivity Probe"
    description = (
        "Verifies WMI/DCOM port 135/tcp reachability and, when WMI credentials "
        "are configured, confirms namespace authentication capability.  This is "
        "a non-invasive informational probe — no changes are made."
    )
    category = "network"
    default_severity = "INFO"
    required_ports = [135]
    service_matchers = ["MS-RPC"]

    requires_credentials: bool = False
    credential_types: List[str] = ["wmi"]

    def run(
        self,
        target: str,
        port: int = 135,
        credential_set: Optional[CredentialSet] = None,
        **kwargs,
    ) -> List[Finding]:
        creds = credential_set or CredentialSet()
        result = _probe_wmi(target, creds)
        if not result.success and "not reachable" in result.message:
            return []

        status = "CONFIRMED" if result.success else "INCONCLUSIVE"
        confidence = 0.9 if result.success else 0.2
        evidence_items = [result.message]
        if result.error:
            evidence_items.append(f"Note: {result.error}")

        return [Finding(
            id=self.check_id,
            title=self.title,
            description=self.description,
            status=status,
            severity="INFO",
            confidence=confidence,
            target=target,
            port=port,
            service="WMI",
            evidence=Evidence(items=evidence_items),
            name=self.title,
        )]
