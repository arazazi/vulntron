"""
SSL/TLS deep inspection module for Vultron PR3.

Performs non-invasive TLS posture analysis via bounded handshake attempts.
This module is purely defensive — it performs read-only handshakes and
does not attempt any exploit or intrusion technique.

Capabilities
------------
- Negotiated protocol version and cipher suite collection
- Certificate chain metadata: expiry, subject/issuer, SANs, sig algo, key size
- Self-signed / untrusted chain detection
- Weak protocol support detection (TLS 1.0, TLS 1.1 where OS permits)
- Weak/deprecated cipher suite flagging (RC4, NULL, EXPORT, ANON, 3DES)
- Forward-secrecy presence indicator
- ALPN / SNI behaviour metadata
- Configurable handshake timeout and retries
- Graceful failure on all handshake and network errors

Dependencies
------------
stdlib only (ssl, socket, datetime, fnmatch) required.
``cryptography`` is used when available for enhanced cert analysis
(signature algorithm, public key size, SANs); graceful fallback otherwise.

Severity model
--------------
CRITICAL  Null cipher (no encryption possible)
HIGH      Weak protocol (TLS 1.0/1.1 accepted), RC4/EXPORT/anonymous cipher,
          expired certificate, hostname mismatch
MEDIUM    Certificate expiring within 30 days, self-signed certificate,
          3DES cipher, no forward secrecy, weak sig algorithm (SHA-1/MD5),
          weak RSA key size (< 2048-bit)
LOW / INFO  Metadata and informational notes
"""

import fnmatch
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Optional cryptography dependency
# ---------------------------------------------------------------------------

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import (
        dsa,
        ec,
        rsa,
    )
    _HAS_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    _HAS_CRYPTOGRAPHY = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Well-known TCP ports that almost exclusively carry TLS traffic
_TLS_PORTS = frozenset({
    443,   # HTTPS
    465,   # SMTPS
    563,   # NNTPS
    636,   # LDAPS
    853,   # DNS-over-TLS
    993,   # IMAPS
    995,   # POP3S
    2484,  # Oracle JDBC-over-TLS
    4443,  # HTTPS alt
    5061,  # SIPS
    5986,  # WinRM HTTPS
    6443,  # Kubernetes API
    7443,  # HTTPS alt
    8443,  # HTTPS alt
    8883,  # MQTT-over-TLS
    9443,  # HTTPS alt
})

# Service name keywords (lower-case) that indicate TLS
_TLS_SERVICE_KEYWORDS = frozenset({
    'https', 'https-alt', 'imaps', 'pop3s', 'ldaps', 'smtps',
    'ftps', 'ssl', 'tls', 'sips', 'k8s-api', 'kubernetes-api',
    'winrm-https',
})

# Protocol version labels for display
_PROTO_DISPLAY: Dict[str, str] = {
    'TLSv1':   'TLS 1.0',
    'TLSv1.1': 'TLS 1.1',
    'TLSv1.2': 'TLS 1.2',
    'TLSv1.3': 'TLS 1.3',
    'SSLv3':   'SSL 3.0',
    'SSLv2':   'SSL 2.0',
}

# Deprecated / legacy protocol versions (HIGH severity)
_LEGACY_PROTOCOLS = frozenset({'TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'})

# Certificate expiry thresholds
_CERT_WARN_DAYS = 30
_CERT_CRITICAL_DAYS = 7

# (cipher_substring, severity, human_description)
_WEAK_CIPHER_RULES: List[Tuple[str, str, str]] = [
    ('NULL',   'CRITICAL', 'NULL cipher — no encryption'),
    ('EXPORT',  'HIGH',    'EXPORT-grade cipher — easily broken'),
    ('AECDH',   'HIGH',    'Anonymous ECDH — no server authentication'),
    ('ADH',     'HIGH',    'Anonymous DH — no server authentication'),
    ('anon',    'HIGH',    'Anonymous cipher — no server authentication'),
    ('RC4',     'HIGH',    'RC4 stream cipher — cryptographically broken'),
    ('RC2',     'HIGH',    'RC2 cipher — deprecated and weak'),
    ('3DES',    'MEDIUM',  'Triple-DES (3DES) — deprecated; SWEET32 attack risk'),
    ('DES',     'HIGH',    '56-bit DES cipher — insufficient key length'),
    ('IDEA',    'MEDIUM',  'IDEA cipher — deprecated'),
    ('MD5',     'MEDIUM',  'MD5 in cipher suite — weak MAC'),
]

# Weak signature algorithms (lower-case OpenSSL name → severity)
_WEAK_SIG_ALGOS: Dict[str, str] = {
    'md5':            'CRITICAL',
    'md2':            'CRITICAL',
    'sha1':           'HIGH',
    'sha1withrsaencryption': 'HIGH',
    'md5withrsaencryption':  'CRITICAL',
}

# Minimum acceptable RSA/DSA key size (bits)
_MIN_RSA_BITS = 2048
_MIN_EC_BITS = 224


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class TLSCertInfo:
    """Parsed certificate metadata.

    All date fields are timezone-aware UTC datetimes when available.
    """

    subject_cn: Optional[str] = None
    subject_san: List[str] = field(default_factory=list)   # DNS SANs
    subject_ip_san: List[str] = field(default_factory=list)  # IP SANs
    issuer_cn: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    is_self_signed: bool = False
    chain_trusted: bool = False           # trusted by system CA store
    sig_algorithm: Optional[str] = None  # e.g. 'sha256WithRSAEncryption'
    public_key_type: Optional[str] = None  # 'RSA', 'EC', 'DSA', etc.
    public_key_bits: Optional[int] = None

    def to_dict(self) -> Dict:
        """Serialise to a plain dict for JSON output."""
        return {
            'subject_cn': self.subject_cn,
            'subject_san': list(self.subject_san),
            'subject_ip_san': list(self.subject_ip_san),
            'issuer_cn': self.issuer_cn,
            'not_before': self.not_before.isoformat() if self.not_before else None,
            'not_after': self.not_after.isoformat() if self.not_after else None,
            'is_self_signed': self.is_self_signed,
            'chain_trusted': self.chain_trusted,
            'sig_algorithm': self.sig_algorithm,
            'public_key_type': self.public_key_type,
            'public_key_bits': self.public_key_bits,
        }


@dataclass
class TLSResult:
    """Full result of a single TLS inspection attempt.

    Attributes
    ----------
    host              Target hostname or IP.
    port              Target TCP port.
    protocol_version  Negotiated TLS version string (e.g. ``'TLSv1.2'``).
    cipher_name       OpenSSL cipher suite name (e.g. ``'ECDHE-RSA-AES256-GCM-SHA384'``).
    cipher_bits       Negotiated cipher key strength in bits.
    has_forward_secrecy  ``True`` when an ephemeral key exchange is in use.
    alpn              Selected ALPN protocol, or ``None``.
    sni_used          Whether SNI was sent in the ClientHello.
    cert_info         Parsed certificate metadata, or ``None`` on failure.
    tls10_accepted    ``True`` if TLS 1.0 handshake succeeded, ``None`` if untested.
    tls11_accepted    ``True`` if TLS 1.1 handshake succeeded, ``None`` if untested.
    error             Error message if the primary handshake failed, else ``None``.
    duration_ms       Approximate handshake duration in milliseconds.
    """

    host: str
    port: int
    protocol_version: Optional[str] = None
    cipher_name: Optional[str] = None
    cipher_bits: Optional[int] = None
    has_forward_secrecy: bool = False
    alpn: Optional[str] = None
    sni_used: bool = False
    cert_info: Optional[TLSCertInfo] = None
    tls10_accepted: Optional[bool] = None
    tls11_accepted: Optional[bool] = None
    error: Optional[str] = None
    duration_ms: Optional[float] = None

    def to_dict(self) -> Dict:
        """Serialise to a plain dict for JSON output."""
        return {
            'host': self.host,
            'port': self.port,
            'protocol_version': self.protocol_version,
            'protocol_display': _PROTO_DISPLAY.get(
                self.protocol_version or '', self.protocol_version or 'unknown'),
            'cipher_name': self.cipher_name,
            'cipher_bits': self.cipher_bits,
            'has_forward_secrecy': self.has_forward_secrecy,
            'alpn': self.alpn,
            'sni_used': self.sni_used,
            'cert_info': self.cert_info.to_dict() if self.cert_info else None,
            'tls10_accepted': self.tls10_accepted,
            'tls11_accepted': self.tls11_accepted,
            'error': self.error,
            'duration_ms': self.duration_ms,
        }

    def to_findings(self, target_host: str) -> List[Dict]:
        """Generate a list of vulnerability-style finding dicts from this result.

        Each finding follows the same schema as the legacy VulnerabilityChecker
        dicts so they can flow through the existing reporting pipeline.
        """
        findings: List[Dict] = []

        if self.error:
            # Handshake failed — note as inconclusive, not a finding
            return findings

        port = self.port
        svc = f'TLS/{port}'

        # --- Cipher checks ---
        if self.cipher_name:
            for substr, severity, desc in _WEAK_CIPHER_RULES:
                if substr in self.cipher_name:
                    findings.append({
                        'id': f'TLS-WEAK-CIPHER-{port}',
                        'cve': 'N/A',
                        'name': 'Weak TLS Cipher Suite',
                        'title': f'Weak/deprecated cipher on port {port}: {self.cipher_name}',
                        'severity': severity,
                        'status': 'CONFIRMED',
                        'port': port,
                        'affected_service': svc,
                        'description': (
                            f'{desc}. Negotiated cipher: {self.cipher_name} '
                            f'({self.cipher_bits} bits) on port {port}/tcp.'
                        ),
                        'evidence': [
                            f'Negotiated cipher suite: {self.cipher_name}',
                            f'Cipher key bits: {self.cipher_bits}',
                            f'Protocol: {_PROTO_DISPLAY.get(self.protocol_version or "", "unknown")}',
                        ],
                        'category': 'tls',
                        'remediation': (
                            'Disable this cipher suite. Configure the server to prefer '
                            'ECDHE/AES-GCM or CHACHA20-POLY1305 cipher suites.'
                        ),
                    })
                    break  # one cipher finding per port

            # Forward secrecy check (skip if cipher already flagged as critical)
            existing_cipher_finding = any(
                f['id'] == f'TLS-WEAK-CIPHER-{port}' for f in findings)
            if not self.has_forward_secrecy and not existing_cipher_finding:
                findings.append({
                    'id': f'TLS-NO-FS-{port}',
                    'cve': 'N/A',
                    'name': 'No TLS Forward Secrecy',
                    'title': f'TLS forward secrecy absent on port {port}',
                    'severity': 'MEDIUM',
                    'status': 'CONFIRMED',
                    'port': port,
                    'affected_service': svc,
                    'description': (
                        f'The negotiated cipher suite ({self.cipher_name}) does not '
                        'provide forward secrecy. Past session traffic could be '
                        'decrypted if the private key is ever compromised.'
                    ),
                    'evidence': [
                        f'Negotiated cipher suite: {self.cipher_name}',
                        'No DHE/ECDHE key exchange prefix detected.',
                    ],
                    'category': 'tls',
                    'remediation': (
                        'Prefer cipher suites with ECDHE or DHE key exchange '
                        '(e.g., ECDHE-RSA-AES256-GCM-SHA384) to enable forward secrecy.'
                    ),
                })

        # --- Protocol version checks ---
        if self.protocol_version in _LEGACY_PROTOCOLS:
            findings.append({
                'id': f'TLS-LEGACY-PROTO-{port}',
                'cve': 'N/A',
                'name': 'Legacy TLS Protocol Negotiated',
                'title': (
                    f'Legacy protocol {_PROTO_DISPLAY.get(self.protocol_version, self.protocol_version)} '
                    f'negotiated on port {port}'
                ),
                'severity': 'HIGH',
                'status': 'CONFIRMED',
                'port': port,
                'affected_service': svc,
                'description': (
                    f'The server negotiated {_PROTO_DISPLAY.get(self.protocol_version, self.protocol_version)} '
                    'which is deprecated and considered insecure. '
                    'TLS 1.0 and 1.1 are vulnerable to POODLE, BEAST, and related attacks.'
                ),
                'evidence': [
                    f'Negotiated protocol version: {self.protocol_version}',
                    f'Cipher suite: {self.cipher_name}',
                ],
                'category': 'tls',
                'remediation': (
                    'Disable TLS 1.0 and TLS 1.1. Configure the server to accept '
                    'TLS 1.2 and TLS 1.3 only.'
                ),
            })

        if self.tls10_accepted is True and self.protocol_version not in _LEGACY_PROTOCOLS:
            findings.append({
                'id': f'TLS-1-0-ACCEPTED-{port}',
                'cve': 'N/A',
                'name': 'TLS 1.0 Accepted',
                'title': f'Server accepts legacy TLS 1.0 on port {port}',
                'severity': 'HIGH',
                'status': 'CONFIRMED',
                'port': port,
                'affected_service': svc,
                'description': (
                    'The server accepted a TLS 1.0 handshake, indicating support '
                    'for a deprecated protocol version vulnerable to POODLE and BEAST.'
                ),
                'evidence': ['TLS 1.0 handshake completed successfully'],
                'category': 'tls',
                'remediation': 'Disable TLS 1.0 support on this service.',
            })

        if self.tls11_accepted is True and self.protocol_version not in _LEGACY_PROTOCOLS:
            findings.append({
                'id': f'TLS-1-1-ACCEPTED-{port}',
                'cve': 'N/A',
                'name': 'TLS 1.1 Accepted',
                'title': f'Server accepts deprecated TLS 1.1 on port {port}',
                'severity': 'HIGH',
                'status': 'CONFIRMED',
                'port': port,
                'affected_service': svc,
                'description': (
                    'The server accepted a TLS 1.1 handshake. TLS 1.1 is deprecated '
                    '(RFC 8996) and should no longer be supported.'
                ),
                'evidence': ['TLS 1.1 handshake completed successfully'],
                'category': 'tls',
                'remediation': 'Disable TLS 1.1 support on this service.',
            })

        # --- Certificate checks ---
        cert = self.cert_info
        if cert:
            now = datetime.now(timezone.utc)

            # Expiry checks
            if cert.not_after is not None:
                if cert.not_after < now:
                    findings.append({
                        'id': f'TLS-CERT-EXPIRED-{port}',
                        'cve': 'N/A',
                        'name': 'Expired TLS Certificate',
                        'title': f'TLS certificate expired on port {port}',
                        'severity': 'HIGH',
                        'status': 'CONFIRMED',
                        'port': port,
                        'affected_service': svc,
                        'description': (
                            f'The TLS certificate expired on '
                            f'{cert.not_after.strftime("%Y-%m-%d")}. '
                            'Clients may reject the connection or show security warnings.'
                        ),
                        'evidence': [
                            f'Certificate notAfter: {cert.not_after.isoformat()}',
                            f'Current time (UTC): {now.isoformat()}',
                            f'Subject CN: {cert.subject_cn or "n/a"}',
                        ],
                        'category': 'tls',
                        'remediation': 'Renew the TLS certificate immediately.',
                    })
                elif cert.not_after < now + timedelta(days=_CERT_CRITICAL_DAYS):
                    days_left = (cert.not_after - now).days
                    findings.append({
                        'id': f'TLS-CERT-EXPIRING-{port}',
                        'cve': 'N/A',
                        'name': 'TLS Certificate Expiring Imminently',
                        'title': f'TLS certificate expires in {days_left} day(s) on port {port}',
                        'severity': 'HIGH',
                        'status': 'CONFIRMED',
                        'port': port,
                        'affected_service': svc,
                        'description': (
                            f'The TLS certificate for this service expires in {days_left} day(s) '
                            f'(on {cert.not_after.strftime("%Y-%m-%d")}). '
                            'Immediate renewal is required.'
                        ),
                        'evidence': [
                            f'Certificate notAfter: {cert.not_after.isoformat()}',
                            f'Days remaining: {days_left}',
                        ],
                        'category': 'tls',
                        'remediation': 'Renew the TLS certificate immediately.',
                    })
                elif cert.not_after < now + timedelta(days=_CERT_WARN_DAYS):
                    days_left = (cert.not_after - now).days
                    findings.append({
                        'id': f'TLS-CERT-EXPIRING-{port}',
                        'cve': 'N/A',
                        'name': 'TLS Certificate Expiring Soon',
                        'title': f'TLS certificate expires in {days_left} day(s) on port {port}',
                        'severity': 'MEDIUM',
                        'status': 'CONFIRMED',
                        'port': port,
                        'affected_service': svc,
                        'description': (
                            f'The TLS certificate expires in {days_left} day(s) '
                            f'(on {cert.not_after.strftime("%Y-%m-%d")}). '
                            'Plan for renewal.'
                        ),
                        'evidence': [
                            f'Certificate notAfter: {cert.not_after.isoformat()}',
                            f'Days remaining: {days_left}',
                        ],
                        'category': 'tls',
                        'remediation': (
                            'Schedule certificate renewal. Standard practice is to renew '
                            'at least 30 days before expiry.'
                        ),
                    })

            # Not-yet-valid
            if cert.not_before is not None and cert.not_before > now:
                findings.append({
                    'id': f'TLS-CERT-NOT-YET-VALID-{port}',
                    'cve': 'N/A',
                    'name': 'TLS Certificate Not Yet Valid',
                    'title': f'TLS certificate validity period has not started on port {port}',
                    'severity': 'HIGH',
                    'status': 'CONFIRMED',
                    'port': port,
                    'affected_service': svc,
                    'description': (
                        f'The certificate notBefore date '
                        f'({cert.not_before.strftime("%Y-%m-%d")}) is in the future. '
                        'This indicates a misconfiguration.'
                    ),
                    'evidence': [
                        f'Certificate notBefore: {cert.not_before.isoformat()}',
                        f'Current time (UTC): {now.isoformat()}',
                    ],
                    'category': 'tls',
                    'remediation': (
                        'Verify the certificate and server clock are correct. '
                        'Reissue the certificate if necessary.'
                    ),
                })

            # Self-signed / untrusted chain
            if cert.is_self_signed:
                findings.append({
                    'id': f'TLS-CERT-SELF-SIGNED-{port}',
                    'cve': 'N/A',
                    'name': 'Self-Signed TLS Certificate',
                    'title': f'Self-signed certificate detected on port {port}',
                    'severity': 'MEDIUM',
                    'status': 'CONFIRMED',
                    'port': port,
                    'affected_service': svc,
                    'description': (
                        'The certificate is self-signed (issuer equals subject). '
                        'Clients cannot verify the identity of this service against '
                        'a trusted CA, enabling man-in-the-middle attacks by an '
                        'attacker with network access.'
                    ),
                    'evidence': [
                        f'Subject CN: {cert.subject_cn or "n/a"}',
                        f'Issuer CN: {cert.issuer_cn or "n/a"}',
                        'Issuer and subject are identical.',
                    ],
                    'category': 'tls',
                    'remediation': (
                        'Replace with a certificate signed by a trusted CA. '
                        'Use Let\'s Encrypt (free) or a commercial CA for public-facing services.'
                    ),
                })
            elif not cert.chain_trusted:
                findings.append({
                    'id': f'TLS-CERT-UNTRUSTED-{port}',
                    'cve': 'N/A',
                    'name': 'Untrusted TLS Certificate Chain',
                    'title': f'Certificate chain not trusted by system CA store on port {port}',
                    'severity': 'MEDIUM',
                    'status': 'CONFIRMED',
                    'port': port,
                    'affected_service': svc,
                    'description': (
                        'The certificate chain could not be verified against the '
                        'system CA store. Clients may show security warnings or '
                        'reject the connection. This may indicate a private/internal CA '
                        'or a misconfigured chain.'
                    ),
                    'evidence': [
                        f'Subject CN: {cert.subject_cn or "n/a"}',
                        f'Issuer CN: {cert.issuer_cn or "n/a"}',
                        'TLS verification against system CAs failed.',
                    ],
                    'category': 'tls',
                    'remediation': (
                        'Ensure the full certificate chain is installed, or replace '
                        'with a certificate from a publicly trusted CA.'
                    ),
                })

            # Weak signature algorithm
            if cert.sig_algorithm:
                sig_lower = cert.sig_algorithm.lower().replace('-', '').replace('_', '')
                for weak_algo, severity in _WEAK_SIG_ALGOS.items():
                    if weak_algo.replace('-', '').replace('_', '') in sig_lower:
                        findings.append({
                            'id': f'TLS-CERT-WEAK-SIG-{port}',
                            'cve': 'N/A',
                            'name': 'Weak Certificate Signature Algorithm',
                            'title': (
                                f'Certificate uses weak signature algorithm '
                                f'({cert.sig_algorithm}) on port {port}'
                            ),
                            'severity': severity,
                            'status': 'CONFIRMED',
                            'port': port,
                            'affected_service': svc,
                            'description': (
                                f'The certificate signature algorithm '
                                f'({cert.sig_algorithm}) is considered weak or broken. '
                                'Certificates should use SHA-256 or stronger.'
                            ),
                            'evidence': [
                                f'Signature algorithm: {cert.sig_algorithm}',
                                f'Subject CN: {cert.subject_cn or "n/a"}',
                            ],
                            'category': 'tls',
                            'remediation': (
                                'Reissue the certificate using SHA-256 (or SHA-384/512) '
                                'as the signature hash algorithm.'
                            ),
                        })
                        break

            # Weak public key
            if cert.public_key_bits is not None and cert.public_key_type:
                key_weak = False
                if cert.public_key_type == 'RSA' and cert.public_key_bits < _MIN_RSA_BITS:
                    key_weak = True
                    min_bits = _MIN_RSA_BITS
                elif cert.public_key_type in ('EC', 'DSA') and cert.public_key_bits < _MIN_EC_BITS:
                    key_weak = True
                    min_bits = _MIN_EC_BITS
                else:
                    min_bits = 0

                if key_weak:
                    findings.append({
                        'id': f'TLS-CERT-WEAK-KEY-{port}',
                        'cve': 'N/A',
                        'name': 'Weak TLS Certificate Key Size',
                        'title': (
                            f'{cert.public_key_type} key too small '
                            f'({cert.public_key_bits}-bit) on port {port}'
                        ),
                        'severity': 'MEDIUM',
                        'status': 'CONFIRMED',
                        'port': port,
                        'affected_service': svc,
                        'description': (
                            f'The certificate uses a {cert.public_key_type} key of only '
                            f'{cert.public_key_bits} bits. The minimum recommended size is '
                            f'{min_bits} bits for {cert.public_key_type}.'
                        ),
                        'evidence': [
                            f'Key type: {cert.public_key_type}',
                            f'Key bits: {cert.public_key_bits}',
                        ],
                        'category': 'tls',
                        'remediation': (
                            f'Reissue the certificate with a {cert.public_key_type} key of '
                            f'at least {min_bits} bits.'
                        ),
                    })

            # Hostname mismatch (when target_host is a resolvable name, not an IP)
            hostname_is_ip = _is_ip_address(target_host)
            if not hostname_is_ip and target_host:
                matched = _hostname_matches_cert(target_host, cert)
                if matched is False:
                    findings.append({
                        'id': f'TLS-CERT-HOSTNAME-MISMATCH-{port}',
                        'cve': 'N/A',
                        'name': 'TLS Certificate Hostname Mismatch',
                        'title': f'Certificate does not match hostname on port {port}',
                        'severity': 'HIGH',
                        'status': 'CONFIRMED',
                        'port': port,
                        'affected_service': svc,
                        'description': (
                            f'The certificate presented on port {port} does not match '
                            f'the target hostname "{target_host}". This may indicate '
                            'certificate misconfiguration or a man-in-the-middle condition.'
                        ),
                        'evidence': [
                            f'Target hostname: {target_host}',
                            f'Certificate CN: {cert.subject_cn or "n/a"}',
                            f'Certificate SANs: {", ".join(cert.subject_san) or "none"}',
                        ],
                        'category': 'tls',
                        'remediation': (
                            'Ensure the certificate covers the target hostname '
                            'via the Subject Alternative Name (SAN) extension.'
                        ),
                    })

        return findings


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _parse_cert_date(date_str: str) -> Optional[datetime]:
    """Parse a certificate date string to a timezone-aware UTC datetime.

    Handles the ``'%b %d %H:%M:%S %Y GMT'`` format produced by Python's
    ``ssl`` module (both space-padded and zero-padded day fields).
    """
    if not date_str:
        return None
    # Normalise multiple spaces to a single space (handles 'Nov  5 ...')
    date_str = ' '.join(date_str.strip().split())
    for fmt in ('%b %d %H:%M:%S %Y GMT', '%b %d %H:%M:%S %Y'):
        try:
            dt = datetime.strptime(date_str, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _is_ip_address(host: str) -> bool:
    """Return True if *host* is an IPv4 or IPv6 address literal."""
    import socket as _socket
    for family in (_socket.AF_INET, _socket.AF_INET6):
        try:
            _socket.inet_pton(family, host)
            return True
        except (_socket.error, OSError):
            pass
    return False


def _hostname_matches_cert(hostname: str, cert: TLSCertInfo) -> Optional[bool]:
    """Check whether *hostname* matches the cert's CN or SANs.

    Returns
    -------
    True   Match found.
    False  No match and at least one name was available to compare.
    None   Not enough cert data to determine.
    """
    names = list(cert.subject_san)  # SANs take precedence
    if not names and cert.subject_cn:
        names = [cert.subject_cn]
    if not names:
        return None

    hostname = hostname.lower()
    for name in names:
        if fnmatch.fnmatch(hostname, name.lower()):
            return True
    return False


def _check_forward_secrecy(cipher_name: str) -> bool:
    """Return True if the cipher name indicates an ephemeral key exchange."""
    if not cipher_name:
        return False
    upper = cipher_name.upper()
    return any(kex in upper for kex in ('ECDHE', 'DHE', 'EDH'))


def _parse_cert_from_stdlib_dict(cert_dict: Dict, trusted: bool) -> TLSCertInfo:
    """Build a :class:`TLSCertInfo` from a stdlib ``ssl.getpeercert()`` dict."""
    subject_cn: Optional[str] = None
    for field_set in cert_dict.get('subject', []):
        for field_name, field_value in field_set:
            if field_name == 'commonName':
                subject_cn = field_value
                break

    issuer_cn: Optional[str] = None
    for field_set in cert_dict.get('issuer', []):
        for field_name, field_value in field_set:
            if field_name == 'commonName':
                issuer_cn = field_value
                break

    san_list = [v for t, v in cert_dict.get('subjectAltName', []) if t == 'DNS']
    ip_san_list = [v for t, v in cert_dict.get('subjectAltName', []) if t == 'IP Address']

    not_after = _parse_cert_date(cert_dict.get('notAfter', ''))
    not_before = _parse_cert_date(cert_dict.get('notBefore', ''))

    is_self_signed = (
        cert_dict.get('issuer') == cert_dict.get('subject')
        and bool(cert_dict.get('subject'))
    )

    return TLSCertInfo(
        subject_cn=subject_cn,
        subject_san=san_list,
        subject_ip_san=ip_san_list,
        issuer_cn=issuer_cn,
        not_before=not_before,
        not_after=not_after,
        is_self_signed=is_self_signed,
        chain_trusted=trusted,
    )


def _parse_cert_from_der(cert_der: bytes, trusted: bool) -> Optional[TLSCertInfo]:
    """Parse a DER-encoded certificate using the ``cryptography`` library.

    Returns ``None`` if ``cryptography`` is not installed or parsing fails.
    """
    if not _HAS_CRYPTOGRAPHY or not cert_der:
        return None
    try:
        cert = x509.load_der_x509_certificate(cert_der)

        # Subject CN
        subject_cn: Optional[str] = None
        try:
            subject_cn = cert.subject.get_attributes_for_oid(
                x509.NameOID.COMMON_NAME)[0].value
        except (IndexError, Exception):
            pass

        # Issuer CN
        issuer_cn: Optional[str] = None
        try:
            issuer_cn = cert.issuer.get_attributes_for_oid(
                x509.NameOID.COMMON_NAME)[0].value
        except (IndexError, Exception):
            pass

        # SANs
        san_list: List[str] = []
        ip_san_list: List[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName)
            san_list = [n.value for n in san_ext.value.get_values_for_type(
                x509.DNSName)]
            ip_san_list = [str(n.value) for n in san_ext.value.get_values_for_type(
                x509.IPAddress)]
        except (x509.ExtensionNotFound, Exception):
            pass

        # Dates (cryptography uses datetime with UTC)
        not_before_dt: Optional[datetime] = None
        not_after_dt: Optional[datetime] = None
        try:
            nb = cert.not_valid_before_utc
            not_before_dt = nb if nb.tzinfo else nb.replace(tzinfo=timezone.utc)
        except Exception:
            pass
        try:
            na = cert.not_valid_after_utc
            not_after_dt = na if na.tzinfo else na.replace(tzinfo=timezone.utc)
        except Exception:
            pass

        # Self-signed
        is_self_signed = (cert.issuer == cert.subject)

        # Signature algorithm
        sig_algo: Optional[str] = None
        try:
            sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
        except Exception:
            pass

        # Public key
        pub_key_type: Optional[str] = None
        pub_key_bits: Optional[int] = None
        try:
            pub_key = cert.public_key()
            if isinstance(pub_key, rsa.RSAPublicKey):
                pub_key_type = 'RSA'
                pub_key_bits = pub_key.key_size
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                pub_key_type = 'EC'
                pub_key_bits = pub_key.key_size
            elif isinstance(pub_key, dsa.DSAPublicKey):
                pub_key_type = 'DSA'
                pub_key_bits = pub_key.key_size
        except Exception:
            pass

        return TLSCertInfo(
            subject_cn=subject_cn,
            subject_san=san_list,
            subject_ip_san=ip_san_list,
            issuer_cn=issuer_cn,
            not_before=not_before_dt,
            not_after=not_after_dt,
            is_self_signed=is_self_signed,
            chain_trusted=trusted,
            sig_algorithm=sig_algo,
            public_key_type=pub_key_type,
            public_key_bits=pub_key_bits,
        )
    except Exception:
        return None


# ---------------------------------------------------------------------------
# is_tls_port utility
# ---------------------------------------------------------------------------


def is_tls_port(port_record: Dict) -> bool:
    """Return True if *port_record* is likely to be a TLS-enabled service.

    A port is considered TLS-eligible when:
    - its port number is in the known TLS port set, OR
    - its service name (lower-case) contains a TLS-related keyword.

    Parameters
    ----------
    port_record:
        A dict from ``PortScanner.scan_port()`` with at least ``port`` and
        ``service`` keys.
    """
    port = port_record.get('port', 0)
    service = (port_record.get('service') or '').lower().strip()

    if port in _TLS_PORTS:
        return True

    for kw in _TLS_SERVICE_KEYWORDS:
        if kw in service:
            return True
    return False


# ---------------------------------------------------------------------------
# TLSInspector
# ---------------------------------------------------------------------------


class TLSInspector:
    """SSL/TLS posture inspector.

    Performs bounded, non-invasive TLS handshakes against discovered services
    to collect security-relevant metadata.

    Parameters
    ----------
    target:   Hostname or IP address of the target.
    timeout:  Per-handshake socket timeout in seconds (default 5.0).
    retries:  Number of connection attempts before giving up (default 2).
    """

    def __init__(
        self,
        target: str,
        timeout: float = 5.0,
        retries: int = 2,
    ):
        self.target = target
        self.timeout = max(0.5, float(timeout))
        self.retries = max(1, int(retries))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def inspect_port(self, port: int) -> TLSResult:
        """Inspect a single port and return a :class:`TLSResult`.

        The method attempts a TLS handshake with ``ssl.CERT_NONE`` for
        reliable connection (including self-signed certs), then separately
        checks whether the certificate is trusted by the system CA store.
        Legacy protocol support (TLS 1.0, TLS 1.1) is probed if the OS
        SSL library permits.
        """
        host = self.target
        sni_host = host if not _is_ip_address(host) else None

        start = datetime.now(timezone.utc)

        for attempt in range(self.retries):
            try:
                # Primary handshake — CERT_NONE for stability
                protocol_version, cipher_name, cipher_bits, alpn, cert_der = \
                    self._primary_handshake(host, port, sni_host)

                duration_ms = (
                    (datetime.now(timezone.utc) - start).total_seconds() * 1000
                )

                has_fs = _check_forward_secrecy(cipher_name or '')

                # Certificate analysis
                cert_info: Optional[TLSCertInfo] = None

                # 1. Try to get a verified cert dict via system CA store
                trusted_cert_dict = self._try_verified_cert(host, port, sni_host)
                if trusted_cert_dict is not None:
                    cert_info = _parse_cert_from_stdlib_dict(trusted_cert_dict, trusted=True)
                    # Enhance with cryptography-parsed data (sig algo, key size)
                    if _HAS_CRYPTOGRAPHY and cert_der:
                        enhanced = _parse_cert_from_der(cert_der, trusted=True)
                        if enhanced:
                            cert_info.sig_algorithm = enhanced.sig_algorithm
                            cert_info.public_key_type = enhanced.public_key_type
                            cert_info.public_key_bits = enhanced.public_key_bits
                elif cert_der and _HAS_CRYPTOGRAPHY:
                    # Cert not trusted by system CAs — parse DER directly
                    cert_info = _parse_cert_from_der(cert_der, trusted=False)

                # Legacy protocol checks (best-effort)
                tls10 = self._try_legacy_version(host, port, sni_host, 'TLSv1')
                tls11 = self._try_legacy_version(host, port, sni_host, 'TLSv1_1')

                return TLSResult(
                    host=host,
                    port=port,
                    protocol_version=protocol_version,
                    cipher_name=cipher_name,
                    cipher_bits=cipher_bits,
                    has_forward_secrecy=has_fs,
                    alpn=alpn,
                    sni_used=sni_host is not None,
                    cert_info=cert_info,
                    tls10_accepted=tls10,
                    tls11_accepted=tls11,
                    duration_ms=round(duration_ms, 1),
                )
            except (OSError, ssl.SSLError, socket.timeout, socket.error) as exc:
                if attempt < self.retries - 1:
                    continue
                return TLSResult(
                    host=host,
                    port=port,
                    error=self._sanitise_error(str(exc)),
                )
        # Should not reach here
        return TLSResult(host=host, port=port, error='all retries exhausted')  # pragma: no cover

    def inspect_ports(self, port_records: List[Dict]) -> Dict[int, TLSResult]:
        """Inspect a list of port records and return results keyed by port number."""
        results: Dict[int, TLSResult] = {}
        for pr in port_records:
            port = pr['port']
            results[port] = self.inspect_port(port)
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _primary_handshake(
        self,
        host: str,
        port: int,
        sni_host: Optional[str],
    ) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[str], Optional[bytes]]:
        """Connect with CERT_NONE to collect protocol / cipher / cert metadata.

        Returns (protocol_version, cipher_name, cipher_bits, alpn, cert_der).
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        raw_sock = socket.create_connection((host, port), timeout=self.timeout)
        try:
            with ctx.wrap_socket(
                raw_sock,
                server_hostname=sni_host or host,
            ) as ssl_sock:
                proto = ssl_sock.version()
                cipher_info = ssl_sock.cipher()  # (name, proto, bits)
                alpn = ssl_sock.selected_alpn_protocol()
                cert_der = ssl_sock.getpeercert(binary_form=True)
                cipher_name = cipher_info[0] if cipher_info else None
                cipher_bits = cipher_info[2] if cipher_info else None
                return proto, cipher_name, cipher_bits, alpn, cert_der
        finally:
            try:
                raw_sock.close()
            except Exception:
                pass

    def _try_verified_cert(
        self,
        host: str,
        port: int,
        sni_host: Optional[str],
    ) -> Optional[Dict]:
        """Try to connect with CA verification; return parsed cert dict or None.

        Returns the stdlib ``getpeercert()`` dict if the cert is trusted by
        the system CA store, ``None`` otherwise (verification failure or
        connection error).
        """
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False  # hostname check done by our own logic
            raw_sock = socket.create_connection((host, port), timeout=self.timeout)
            try:
                with ctx.wrap_socket(
                    raw_sock,
                    server_hostname=sni_host or host,
                ) as ssl_sock:
                    return ssl_sock.getpeercert()
            finally:
                try:
                    raw_sock.close()
                except Exception:
                    pass
        except ssl.SSLCertVerificationError:
            return None
        except Exception:
            return None

    def _try_legacy_version(
        self,
        host: str,
        port: int,
        sni_host: Optional[str],
        version_attr: str,
    ) -> Optional[bool]:
        """Attempt a handshake with a specific legacy TLS version.

        Returns
        -------
        True   Handshake succeeded (server supports this version).
        False  Handshake failed at SSL level (server rejected this version).
        None   Could not test (OS/OpenSSL policy disallows this version,
               or the connection itself could not be established).
        """
        if not hasattr(ssl.TLSVersion, version_attr):
            return None
        try:
            tls_ver = getattr(ssl.TLSVersion, version_attr)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = tls_ver
            ctx.maximum_version = tls_ver
            raw_sock = socket.create_connection((host, port), timeout=self.timeout)
            try:
                with ctx.wrap_socket(
                    raw_sock,
                    server_hostname=sni_host or host,
                ):
                    return True
            finally:
                try:
                    raw_sock.close()
                except Exception:
                    pass
        except ssl.SSLError:
            return False
        except Exception:
            return None

    @staticmethod
    def _sanitise_error(msg: str) -> str:
        """Return a short sanitised error string safe for report output."""
        # Truncate long messages and strip potentially sensitive details
        if len(msg) > 120:
            msg = msg[:120] + '...'
        return msg
