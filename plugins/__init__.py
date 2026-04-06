"""
Vultron plugin framework — Phase A + PR1 foundation.

This package provides the core types needed to write and register
vulnerability checks, including the PR1 credentialed scanning framework:

    BaseCheck               Abstract base class every check must subclass.
    CheckRegistry           Global check registry for registration and discovery.
    Finding                 Unified finding data model (single source of truth).
    ScanMetadata            Scan-level metadata model.
    Evidence                Structured evidence container.

PR1 additions:

    SSHCredential           SSH credential model (password or key-based).
    WinRMCredential         WinRM credential model (username/password/domain).
    WMICredential           WMI credential model (username/password/domain).
    CredentialSet           Container for all credential types.
    CredentialValidationError  Raised when a credential fails validation.
    CredentialProvider      Abstract interface for credential providers.
    InlineCredentialProvider  Provider backed by an explicit CredentialSet.
    EnvCredentialProvider   Provider backed by environment variables.
    FileCredentialProvider  Provider backed by a JSON credentials file.
    ChainedCredentialProvider Try multiple providers in priority order.
    build_default_provider  Factory for the default chained provider.
    AuthenticatedExecutor   Execute authenticated probes for a target.
    AuthSessionContext      Runtime state for one authenticated scan session.
    ProbeResult             Result of a single protocol connectivity probe.
    mask_secret             Mask a secret value for safe logging.
    redact_dict             Redact sensitive keys in a dict.
    deep_redact_dict        Recursively redact sensitive keys.
    redact_string           Redact inline secret assignments in a string.
    REDACTED                Sentinel replacement token.

Quick-start — adding a new check
---------------------------------
::

    from plugins import BaseCheck, CheckRegistry, Evidence, Finding

    @CheckRegistry.register
    class MyCheck(BaseCheck):
        check_id         = 'MY-CHECK-001'
        title            = 'My Service Exposure'
        description      = 'Detects exposure of My Service on port 9999.'
        category         = 'network'
        default_severity = 'HIGH'
        required_ports   = [9999]
        service_matchers = ['MyService']

        def run(self, target: str, port: int = 9999, **kwargs):
            import socket
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((target, port))
                sock.close()
                return [Finding(
                    id=self.check_id, title=self.title,
                    description='My Service is reachable from an external host.',
                    status='CONFIRMED', severity=self.default_severity,
                    confidence=0.9, target=target, port=port,
                    service='MyService',
                    evidence=Evidence(items=[f'Port {port}/tcp is open']),
                    remediation='Restrict access via firewall.',
                )]
            except socket.timeout:
                return [Finding(
                    id=self.check_id, title=self.title + ' — check inconclusive',
                    description='Probe timed out.',
                    status='INCONCLUSIVE', severity=self.default_severity,
                    confidence=0.2, target=target, port=port,
                )]
            except Exception:
                return []

Place the file in ``plugins/checks/`` and import it from
``plugins/checks/__init__.py`` so it is auto-discovered at startup.
"""

from .base import BaseCheck
from .registry import CheckRegistry
from .schema import Evidence, Finding, ScanMetadata
from .credentials import (
    CredentialSet,
    CredentialValidationError,
    SSHCredential,
    WinRMCredential,
    WMICredential,
)
from .providers import (
    CredentialProvider,
    InlineCredentialProvider,
    EnvCredentialProvider,
    FileCredentialProvider,
    ChainedCredentialProvider,
    build_default_provider,
)
from .auth_executor import AuthenticatedExecutor, AuthSessionContext, ProbeResult
from .secrets import REDACTED, mask_secret, redact_dict, deep_redact_dict, redact_string
from .inventory import (
    AssetRecord,
    InventoryBuilder,
    InventorySnapshot,
    HostProfiler,
    OsHint,
    ServiceRecord,
    TLSServiceRecord,
    persist_inventory,
)

__all__ = [
    # Phase A
    "BaseCheck",
    "CheckRegistry",
    "Evidence",
    "Finding",
    "ScanMetadata",
    # PR1 — credentials
    "CredentialSet",
    "CredentialValidationError",
    "SSHCredential",
    "WinRMCredential",
    "WMICredential",
    # PR1 — providers
    "CredentialProvider",
    "InlineCredentialProvider",
    "EnvCredentialProvider",
    "FileCredentialProvider",
    "ChainedCredentialProvider",
    "build_default_provider",
    # PR1 — auth executor
    "AuthenticatedExecutor",
    "AuthSessionContext",
    "ProbeResult",
    # PR1 — secrets
    "REDACTED",
    "mask_secret",
    "redact_dict",
    "deep_redact_dict",
    "redact_string",
    # PR4 — asset inventory
    "AssetRecord",
    "InventoryBuilder",
    "InventorySnapshot",
    "HostProfiler",
    "OsHint",
    "ServiceRecord",
    "TLSServiceRecord",
    "persist_inventory",
]
