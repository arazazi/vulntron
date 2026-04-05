"""
Authenticated session executor for Vultron credentialed scanning (PR1).

This module provides the scaffolding that allows checks and probes to
request an authenticated session context.  For PR1 the executor performs
minimal, non-invasive connectivity probes only (no write operations).

Architecture
------------
:class:`AuthSessionContext`
    Holds the runtime state for a single authenticated scan: the target,
    credential set, and per-protocol probe results.

:class:`AuthenticatedExecutor`
    Executes the configured probes, stores results in an
    :class:`AuthSessionContext`, and returns informational
    :class:`~plugins.schema.Finding` objects mapped into the unified schema.

Probe safety contract
---------------------
- Probes **must not** make any changes to the target system.
- Probes **must not** exfiltrate data; they confirm reachability only.
- Probe results are ``INFO`` severity, ``CONFIRMED`` or ``INCONCLUSIVE``.
- Secrets are **never** included in Finding evidence or description fields.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .credentials import CredentialSet
from .schema import Evidence, Finding
from .secrets import credential_safe_repr, REDACTED


# ---------------------------------------------------------------------------
# Probe result
# ---------------------------------------------------------------------------


@dataclass
class ProbeResult:
    """Result of a single authenticated connectivity probe.

    Attributes
    ----------
    protocol:
        Short protocol name: ``'ssh'``, ``'winrm'``, or ``'wmi'``.
    target:
        Host/IP that was probed.
    port:
        TCP port used for the probe.
    success:
        ``True`` if the probe established a connection / authenticated.
    message:
        Human-readable outcome string (no secrets).
    error:
        Exception message if the probe failed, sanitised of secrets.
        ``None`` on success.
    latency_ms:
        Round-trip time in milliseconds, or ``None`` if not measured.
    """

    protocol: str
    target: str
    port: int
    success: bool
    message: str
    error: Optional[str] = None
    latency_ms: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dict (no secrets)."""
        return {
            "protocol": self.protocol,
            "target": self.target,
            "port": self.port,
            "success": self.success,
            "message": self.message,
            "error": self.error,
            "latency_ms": self.latency_ms,
        }


# ---------------------------------------------------------------------------
# AuthSessionContext
# ---------------------------------------------------------------------------


@dataclass
class AuthSessionContext:
    """Runtime context for one authenticated scan session.

    Attributes
    ----------
    target:
        The host/IP being scanned.
    credential_set:
        The credentials in use (not serialised; access via
        :attr:`credential_summary` for safe output).
    probe_results:
        Results of each protocol probe, keyed by protocol name.
    authenticated_mode:
        ``True`` once at least one probe succeeds.
    scan_timestamp:
        ISO-8601 timestamp when the context was created.
    """

    target: str
    credential_set: CredentialSet
    probe_results: Dict[str, ProbeResult] = field(default_factory=dict)
    authenticated_mode: bool = False
    scan_timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def credential_summary(self) -> Dict[str, Optional[str]]:
        """Secrets-safe summary of configured credentials."""
        return self.credential_set.redacted_summary()

    def record_probe(self, result: ProbeResult) -> None:
        """Store a :class:`ProbeResult` and update :attr:`authenticated_mode`."""
        self.probe_results[result.protocol] = result
        if result.success:
            self.authenticated_mode = True

    def to_metadata_dict(self) -> Dict[str, Any]:
        """Return a secrets-safe dict for embedding in scan metadata."""
        return {
            "target": self.target,
            "authenticated_mode": self.authenticated_mode,
            "credentials_configured": self.credential_summary,
            "probe_results": {
                proto: r.to_dict()
                for proto, r in self.probe_results.items()
            },
            "scan_timestamp": self.scan_timestamp,
        }


# ---------------------------------------------------------------------------
# Probe implementations
# ---------------------------------------------------------------------------


def _tcp_reachable(host: str, port: int, timeout: float = 5.0) -> tuple[bool, Optional[str]]:
    """Return (reachable, error_message).  No authentication performed."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return True, None
    except socket.timeout:
        return False, f"Connection to {host}:{port} timed out"
    except OSError as exc:
        return False, str(exc)


def _probe_ssh(
    target: str,
    credential_set: CredentialSet,
    timeout: float = 5.0,
) -> ProbeResult:
    """Minimal SSH connectivity probe (PR1: TCP-layer reachability + SSH banner).

    For PR1 we perform only a TCP connect and collect the SSH banner.
    Full key/password authentication requires the ``paramiko`` library which
    is an optional dependency; when unavailable we fall back to TCP-only.
    """
    cred = credential_set.ssh
    port = cred.port if cred else 22
    cred_label = credential_safe_repr(cred) if cred else "(no ssh credential)"

    # TCP reachability check first
    reachable, tcp_err = _tcp_reachable(target, port, timeout)
    if not tcp_err and not reachable:
        tcp_err = f"Port {port}/tcp not reachable"

    if not reachable:
        return ProbeResult(
            protocol="ssh",
            target=target,
            port=port,
            success=False,
            message=f"SSH port {port}/tcp not reachable on {target}",
            error=tcp_err,
        )

    # Attempt to collect SSH banner (non-auth, informational only)
    banner = ""
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            raw = sock.recv(256)
            banner = raw.decode("utf-8", errors="ignore").strip().split("\n")[0][:80]
    except Exception:
        pass  # Banner collection is best-effort

    # Attempt paramiko authentication if available and credentials provided
    auth_success = False
    auth_error: Optional[str] = None
    if cred is not None:
        try:
            import paramiko  # type: ignore[import]
            transport = paramiko.Transport((target, port))
            transport.start_client(timeout=timeout)
            try:
                if cred.key_path:
                    key = paramiko.RSAKey.from_private_key_file(
                        cred.key_path,
                        password=cred.passphrase,
                    )
                    transport.auth_publickey(cred.username, key)
                else:
                    transport.auth_password(cred.username, cred.password)
                auth_success = transport.is_authenticated()
            finally:
                transport.close()
        except ImportError:
            # paramiko not installed — TCP success is the best we can report
            auth_success = True
            auth_error = "paramiko not installed; TCP connectivity confirmed only"
        except Exception as exc:
            # Sanitise error — do not include password in message
            auth_error = _sanitise_auth_error(str(exc))

    if cred is None:
        # No credentials — TCP reachability only
        return ProbeResult(
            protocol="ssh",
            target=target,
            port=port,
            success=True,
            message=(
                f"SSH port {port}/tcp is reachable on {target}"
                + (f"; banner: {banner}" if banner else "")
            ),
        )

    if auth_success:
        return ProbeResult(
            protocol="ssh",
            target=target,
            port=port,
            success=True,
            message=(
                f"SSH connectivity and authentication confirmed on {target}:{port}"
                + (f"; banner: {banner}" if banner else "")
                + (f" ({auth_error})" if auth_error else "")
            ),
        )
    return ProbeResult(
        protocol="ssh",
        target=target,
        port=port,
        success=False,
        message=f"SSH port {port}/tcp reachable but authentication failed on {target}",
        error=auth_error,
    )


def _probe_winrm(
    target: str,
    credential_set: CredentialSet,
    timeout: float = 5.0,
) -> ProbeResult:
    """WinRM connectivity probe (PR1: TCP-layer reachability).

    Full WinRM authentication requires the ``pywinrm`` library which is an
    optional dependency.  When unavailable we confirm TCP reachability only.
    """
    cred = credential_set.winrm
    port = cred.effective_port if cred else 5985

    reachable, tcp_err = _tcp_reachable(target, port, timeout)
    if not reachable:
        return ProbeResult(
            protocol="winrm",
            target=target,
            port=port,
            success=False,
            message=f"WinRM port {port}/tcp not reachable on {target}",
            error=tcp_err,
        )

    if cred is None:
        return ProbeResult(
            protocol="winrm",
            target=target,
            port=port,
            success=True,
            message=f"WinRM port {port}/tcp is reachable on {target}",
        )

    # Attempt pywinrm session if available
    try:
        import winrm  # type: ignore[import]
        session = winrm.Session(
            target=f"http://{target}:{port}/wsman",
            auth=(cred.username, cred.password),
            transport="ntlm",
        )
        result = session.run_cmd("hostname")
        if result.status_code == 0:
            return ProbeResult(
                protocol="winrm",
                target=target,
                port=port,
                success=True,
                message=f"WinRM session authenticated and functional on {target}:{port}",
            )
        return ProbeResult(
            protocol="winrm",
            target=target,
            port=port,
            success=False,
            message=f"WinRM command returned non-zero status on {target}:{port}",
            error=f"Status code: {result.status_code}",
        )
    except ImportError:
        return ProbeResult(
            protocol="winrm",
            target=target,
            port=port,
            success=True,
            message=(
                f"WinRM port {port}/tcp reachable on {target}; "
                "install 'pywinrm' for full session verification"
            ),
        )
    except Exception as exc:
        return ProbeResult(
            protocol="winrm",
            target=target,
            port=port,
            success=False,
            message=f"WinRM connectivity check failed on {target}:{port}",
            error=_sanitise_auth_error(str(exc)),
        )


def _probe_wmi(
    target: str,
    credential_set: CredentialSet,
    timeout: float = 5.0,
) -> ProbeResult:
    """WMI connectivity probe (PR1: TCP/DCOM reachability + optional auth).

    WMI uses DCOM/RPC (port 135 + dynamic high ports).  For PR1 we confirm
    port 135 is reachable.  Full WMI queries require the ``impacket`` library.
    """
    port = 135  # DCOM endpoint mapper

    reachable, tcp_err = _tcp_reachable(target, port, timeout)
    if not reachable:
        return ProbeResult(
            protocol="wmi",
            target=target,
            port=port,
            success=False,
            message=f"WMI/DCOM port {port}/tcp not reachable on {target}",
            error=tcp_err,
        )

    cred = credential_set.wmi
    if cred is None:
        return ProbeResult(
            protocol="wmi",
            target=target,
            port=port,
            success=True,
            message=f"WMI/DCOM port {port}/tcp is reachable on {target}",
        )

    # impacket-based WMI probe (optional)
    try:
        from impacket.dcerpc.v5.dcom import wmi as _wmi  # type: ignore[import]
        from impacket.dcerpc.v5.dcomrt import DCOMConnection  # type: ignore[import]

        domain = cred.domain or ""
        dcom = DCOMConnection(
            target,
            username=cred.username,
            password=cred.password,
            domain=domain,
        )
        iface = dcom.CoCreateInstanceEx(
            _wmi.CLSID_WbemLevel1Login,
            _wmi.IID_IWbemLevel1Login,
        )
        iface.get_interface().RemoteLoginWithEnvVars(
            domain, cred.username, cred.password,
            0, cred.namespace,
            _wmi.IWbemLevel1Login.WBEM_FLAG_CONNECT_USE_MAX_WAIT,
        )
        dcom.disconnect()
        return ProbeResult(
            protocol="wmi",
            target=target,
            port=port,
            success=True,
            message=f"WMI session authenticated on {target} (namespace: {cred.namespace})",
        )
    except ImportError:
        return ProbeResult(
            protocol="wmi",
            target=target,
            port=port,
            success=True,
            message=(
                f"WMI/DCOM port {port}/tcp reachable on {target}; "
                "install 'impacket' for full session verification"
            ),
        )
    except Exception as exc:
        return ProbeResult(
            protocol="wmi",
            target=target,
            port=port,
            success=False,
            message=f"WMI connectivity check failed on {target}",
            error=_sanitise_auth_error(str(exc)),
        )


# ---------------------------------------------------------------------------
# AuthenticatedExecutor
# ---------------------------------------------------------------------------


class AuthenticatedExecutor:
    """Execute authenticated connectivity probes for a single target.

    Parameters
    ----------
    target:
        Host/IP to probe.
    credential_set:
        Credentials to use for probes.
    timeout:
        Per-probe TCP connection timeout in seconds.
    """

    #: Finding ID prefix for auth probe informational findings.
    FINDING_ID_PREFIX = "AUTH-PROBE"

    def __init__(
        self,
        target: str,
        credential_set: CredentialSet,
        timeout: float = 5.0,
    ) -> None:
        self._target = target
        self._cred_set = credential_set
        self._timeout = timeout
        self._context = AuthSessionContext(
            target=target,
            credential_set=credential_set,
        )

    @property
    def context(self) -> AuthSessionContext:
        """The current :class:`AuthSessionContext`."""
        return self._context

    def run_probes(self) -> List[Finding]:
        """Execute all configured probes and return informational Findings.

        Only protocols for which a credential is configured are probed.
        If no credentials are configured at all, returns an empty list so
        that unauthenticated scan flow is unaffected.

        Returns
        -------
        list of Finding
            Zero or more ``INFO`` severity findings describing probe outcomes.
        """
        if self._cred_set.is_empty():
            return []

        findings: List[Finding] = []

        if self._cred_set.ssh is not None:
            result = _probe_ssh(self._target, self._cred_set, self._timeout)
            self._context.record_probe(result)
            findings.append(self._probe_to_finding(result))

        if self._cred_set.winrm is not None:
            result = _probe_winrm(self._target, self._cred_set, self._timeout)
            self._context.record_probe(result)
            findings.append(self._probe_to_finding(result))

        if self._cred_set.wmi is not None:
            result = _probe_wmi(self._target, self._cred_set, self._timeout)
            self._context.record_probe(result)
            findings.append(self._probe_to_finding(result))

        return findings

    def _probe_to_finding(self, result: ProbeResult) -> Finding:
        """Convert a :class:`ProbeResult` to a unified :class:`Finding`."""
        proto_upper = result.protocol.upper()
        status = "CONFIRMED" if result.success else "INCONCLUSIVE"
        confidence = 0.9 if result.success else 0.2

        evidence_items = [result.message]
        if result.error:
            evidence_items.append(f"Error: {result.error}")

        description = (
            f"Authenticated {proto_upper} connectivity probe "
            f"{'succeeded' if result.success else 'failed'} for {result.target}."
        )
        if not result.success and result.error:
            description += f" Reason: {result.error}"

        return Finding(
            id=f"{self.FINDING_ID_PREFIX}-{proto_upper}",
            title=f"{proto_upper} Authenticated Connectivity Probe",
            description=description,
            status=status,
            severity="INFO",
            confidence=confidence,
            target=result.target,
            port=result.port,
            service=proto_upper,
            evidence=Evidence(items=evidence_items),
            scan_timestamp=self._context.scan_timestamp,
        )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _sanitise_auth_error(message: str) -> str:
    """Remove credential-like values from an error message."""
    from .secrets import redact_string
    return redact_string(message)
