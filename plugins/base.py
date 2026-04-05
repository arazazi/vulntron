"""
Abstract base class for all Vultron plugin checks.

Every check must subclass :class:`BaseCheck` and implement :meth:`run`.
Class-level attributes describe the check and drive registry dispatch.

Example
-------
::

    from plugins import BaseCheck, CheckRegistry, Evidence, Finding

    @CheckRegistry.register
    class MyServiceCheck(BaseCheck):
        check_id        = 'MY-SERVICE-001'
        title           = 'My Service Exposure'
        description     = 'Detects insecure exposure of My Service.'
        category        = 'network'
        default_severity = 'HIGH'
        required_ports  = [12345]
        service_matchers = ['MyService']

        def run(self, target: str, port: int = 12345, **kwargs):
            # ... perform probe ...
            return [Finding(
                id=self.check_id, title=self.title, description=self.description,
                status='CONFIRMED', severity=self.default_severity,
                confidence=0.9, target=target, port=port, ...
            )]
"""

import abc
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from .schema import Finding


class BaseCheck(abc.ABC):
    """Abstract base class for all vulnerability checks.

    Subclasses **must** define all class-level attributes and implement
    :meth:`run`.  The attributes are used by :class:`~plugins.registry.CheckRegistry`
    for discovery and dispatch.

    Class attributes
    ----------------
    check_id
        Stable identifier string (e.g. ``'MS17-010'``, ``'FTP-ANON'``).
        Must be unique across all registered checks.
    title
        Short human-readable title shown in reports.
    description
        Full description of what the check tests.
    category
        One of ``'network'``, ``'service'``, or ``'config'``.
    default_severity
        Default severity when creating a finding: ``CRITICAL``, ``HIGH``,
        ``MEDIUM``, ``LOW``, or ``INFO``.
    required_ports
        List of TCP/UDP port numbers this check applies to.
        The registry uses this for automatic dispatch.
    service_matchers
        List of service-name strings (case-insensitive) this check applies to
        (e.g. ``['SMB', 'SAMBA']``).
    """

    #: Stable check identifier
    check_id: str = ""
    #: Short human-readable title
    title: str = ""
    #: Full description
    description: str = ""
    #: Category: 'network' | 'service' | 'config'
    category: str = "network"
    #: Default severity string
    default_severity: str = "MEDIUM"
    #: Ports this check applies to
    required_ports: List[int] = []
    #: Service name strings this check applies to (case-insensitive)
    service_matchers: List[str] = []
    #: Whether this check **requires** credentials to run.
    #: When ``True`` and no credentials are provided, the check must return
    #: an explicit SKIP finding rather than raising an exception.
    requires_credentials: bool = False
    #: Credential types accepted by this check (e.g. ``['ssh', 'winrm']``).
    #: Empty list means the check does not use credentials.
    credential_types: List[str] = []

    @abc.abstractmethod
    def run(self, target: str, port: int, **kwargs) -> List["Finding"]:
        """Execute the check and return zero or more :class:`~plugins.schema.Finding` objects.

        Parameters
        ----------
        target:
            The host/IP address to probe.
        port:
            The TCP/UDP port number to use for the probe.
        **kwargs:
            Reserved for future extension (e.g. credentials, timeout override).

        Returns
        -------
        list of Finding
            An empty list if the host is not affected or no result could be
            determined.  Never raise exceptions — return an INCONCLUSIVE
            finding instead.
        """
        ...
