"""
Vultron plugin framework — Phase A foundation.

This package provides the core types needed to write and register
vulnerability checks:

    BaseCheck       Abstract base class every check must subclass.
    CheckRegistry   Global check registry for registration and discovery.
    Finding         Unified finding data model (single source of truth).
    ScanMetadata    Scan-level metadata model.
    Evidence        Structured evidence container.

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

__all__ = [
    "BaseCheck",
    "CheckRegistry",
    "Evidence",
    "Finding",
    "ScanMetadata",
]
