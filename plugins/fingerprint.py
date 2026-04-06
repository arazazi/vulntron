"""
Service fingerprinting utilities for Vultron PR2.

Provides banner-based service name normalisation and version extraction
with an associated confidence score, for both TCP and UDP discovered services.

Confidence levels
-----------------
0.9  Banner pattern matched — high-confidence service identification.
0.5  Port-number lookup matched — service is a reasonable assumption.
0.2  No match found — service identity is unknown.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Canonical service name normalisation table
# ---------------------------------------------------------------------------

# Maps lower-case raw names (with spaces replaced by hyphens) to canonical
# display names.  Applied after port-table lookup to ensure consistent output.
_SERVICE_NORM: Dict[str, str] = {
    'http-proxy':  'HTTP',
    'http-alt':    'HTTP',
    'http-alt2':   'HTTP',
    'http-alt3':   'HTTP',
    'https-alt':   'HTTPS',
    'ms-rpc-dyn':  'MS-RPC',
    'netbios':     'NetBIOS',
    'netbios-ns':  'NetBIOS-NS',
    'netbios-dgm': 'NetBIOS-DGM',
    'snmp-trap':   'SNMP-TRAP',
    'ike-nat':     'IKE',
    'mdns':        'mDNS',
    'ftp-data':    'FTP-DATA',
    'smtp-tls':    'SMTP',
    'k8s-api':     'Kubernetes-API',
}


def normalize_service_name(name: str) -> str:
    """Return a canonical display name for *name*.

    The lookup key is the lower-cased input with spaces replaced by hyphens.
    Names not found in the normalisation table are returned in upper-case.

    Examples
    --------
    >>> normalize_service_name('http-proxy')
    'HTTP'
    >>> normalize_service_name('SSH')
    'SSH'
    """
    key = name.lower().replace(' ', '-')
    return _SERVICE_NORM.get(key, name.upper())


# ---------------------------------------------------------------------------
# Banner-based fingerprint patterns
# ---------------------------------------------------------------------------

# Each entry: (compiled_regex, canonical_service_name, version_capture_group)
# version_capture_group is an int (group index) or None when not applicable.
_BannerPattern = Tuple[re.Pattern, str, Optional[int]]

_BANNER_PATTERNS: List[_BannerPattern] = [
    # SSH: "SSH-2.0-OpenSSH_8.9p1"
    (re.compile(r'^SSH-(\d[\d.]+)-(\S+)', re.I), 'SSH', 2),
    # FTP greeting
    (re.compile(r'^220[- ].*\bftp\b', re.I), 'FTP', None),
    # SMTP greeting
    (re.compile(r'^220[- ].*\bsmtp\b', re.I | re.S), 'SMTP', None),
    # HTTP response
    (re.compile(r'HTTP/\d[.\d]*\s+\d{3}', re.I), 'HTTP', None),
    # VNC: "RFB 003.008"
    (re.compile(r'^RFB\s+(\d+\.\d+)', re.I), 'VNC', 1),
    # MySQL / MariaDB banner
    (re.compile(r'mysql_native_password|MariaDB', re.I), 'MySQL', None),
    # Microsoft SQL Server
    (re.compile(r'Microsoft SQL Server', re.I), 'MSSQL', None),
    # Redis
    (re.compile(r'\bRedis\b|NOAUTH|WRONGTYPE', re.I), 'Redis', None),
    # PostgreSQL
    (re.compile(r'PostgreSQL|pg_hba', re.I), 'PostgreSQL', None),
    # SNMP response (starts with SEQUENCE 0x30)
    (re.compile(r'^\x30'), 'SNMP', None),
    # DNS response (transaction ID echo 0x13 0x37 from our probe + flags)
    (re.compile(r'^\x13\x37', re.S), 'DNS', None),
]


# ---------------------------------------------------------------------------
# ServiceFingerprint dataclass
# ---------------------------------------------------------------------------

@dataclass
class ServiceFingerprint:
    """Result of fingerprinting a discovered service.

    Attributes
    ----------
    service:    Normalised service name (e.g. ``HTTP``, ``SSH``).
    version:    Extracted version string, or ``None`` if unknown.
    protocol:   Transport protocol: ``tcp`` or ``udp``.
    confidence: Float 0.0–1.0 representing identification certainty.
                0.9 = banner matched, 0.5 = port-only, 0.2 = unknown.
    evidence:   Human-readable strings supporting this fingerprint.
    """

    service: str
    version: Optional[str] = None
    protocol: str = 'tcp'
    confidence: float = 0.5
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Serialise to a plain dict suitable for embedding in port records."""
        return {
            'service': self.service,
            'version': self.version,
            'protocol': self.protocol,
            'confidence': self.confidence,
            'evidence': list(self.evidence),
        }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def fingerprint_banner(
    banner: str,
    port: int,
    protocol: str = 'tcp',
    known_service: Optional[str] = None,
) -> ServiceFingerprint:
    """Identify a service from its *banner* string.

    The function first attempts to match the banner against a set of
    protocol-specific patterns.  If no pattern matches, it falls back to
    *known_service* (the name from the port-table lookup) normalised via
    :func:`normalize_service_name`.  If that is also absent, a low-confidence
    ``Unknown-<port>`` fingerprint is returned.

    Parameters
    ----------
    banner:        Raw text received from the service (may be empty).
    port:          Port number — used for the fallback lookup.
    protocol:      ``'tcp'`` or ``'udp'``.
    known_service: Service name already determined by port-table lookup.

    Returns
    -------
    :class:`ServiceFingerprint`
        Best-available fingerprint with confidence score and evidence.
    """
    if banner:
        for pattern, svc_name, ver_group in _BANNER_PATTERNS:
            m = pattern.search(banner)
            if m:
                version: Optional[str] = None
                if ver_group is not None:
                    try:
                        version = m.group(ver_group)
                    except IndexError:
                        pass
                return ServiceFingerprint(
                    service=svc_name,
                    version=version,
                    protocol=protocol,
                    confidence=0.9,
                    evidence=[f'Banner match ({svc_name}): {banner[:80]}'],
                )

    # Fall back to the port-table service name
    if known_service:
        norm = normalize_service_name(known_service)
        return ServiceFingerprint(
            service=norm,
            version=None,
            protocol=protocol,
            confidence=0.5,
            evidence=[f'Port {port}/{protocol} maps to {known_service}'],
        )

    return ServiceFingerprint(
        service=f'Unknown-{port}',
        version=None,
        protocol=protocol,
        confidence=0.2,
        evidence=[f'Port {port}/{protocol}: no matching service name'],
    )
