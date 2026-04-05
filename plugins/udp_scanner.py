"""
UDP port scanning engine for Vultron PR2.

Implements practical UDP port scanning with:
  - Protocol-aware probes (DNS, NTP, SNMP)
  - State classification: open, open|filtered, closed
  - Configurable timeout, retries, and concurrency

State semantics
---------------
open          Response received — service is responding to the probe.
open|filtered No response and no ICMP error — port may be open or filtered.
closed        ICMP port-unreachable received — port is definitively closed.
"""

import socket
import struct
from typing import Dict, List, Optional

try:
    from concurrent.futures import ThreadPoolExecutor, as_completed
    _HAS_THREADING = True
except ImportError:  # pragma: no cover
    _HAS_THREADING = False


# ---------------------------------------------------------------------------
# Common UDP service names
# ---------------------------------------------------------------------------

UDP_SERVICE_NAMES: Dict[int, str] = {
    53:   'DNS',
    67:   'DHCP',
    68:   'DHCP',
    69:   'TFTP',
    123:  'NTP',
    137:  'NetBIOS-NS',
    138:  'NetBIOS-DGM',
    161:  'SNMP',
    162:  'SNMP-TRAP',
    500:  'IKE',
    514:  'Syslog',
    520:  'RIP',
    1194: 'OpenVPN',
    1900: 'SSDP',
    4500: 'IKE-NAT',
    5353: 'mDNS',
}

# Canonical default scan list for UDP mode
UDP_DEFAULT_PORTS: List[int] = sorted(UDP_SERVICE_NAMES.keys())


# ---------------------------------------------------------------------------
# Protocol-aware probe builders
# ---------------------------------------------------------------------------

def _build_dns_probe() -> bytes:
    """Build a minimal DNS query for 'version.bind' (TXT/CH class).

    This is a standard, read-only query that many DNS resolvers respond to
    and is used as a lightweight liveness probe.
    """
    # Header: TxID=0x1337, Flags=0x0100 (standard query), QDCount=1
    header = struct.pack('>HHHHHH', 0x1337, 0x0100, 1, 0, 0, 0)
    # QNAME: 'version.bind' in DNS wire format
    name = b'\x07version\x04bind\x00'
    # QTYPE=TXT (16), QCLASS=CH (3) — chaos class used for version queries
    question = name + struct.pack('>HH', 16, 3)
    return header + question


def _build_ntp_probe() -> bytes:
    """Build a minimal NTP client Mode 3 request (48 bytes).

    LI=0 (no warning), VN=3 (version 3), Mode=3 (client).
    The first byte encodes these as: 0b00_011_011 = 0x1B.
    """
    pkt = bytearray(48)
    pkt[0] = 0x1B
    return bytes(pkt)


def _build_snmp_probe(community: str = 'public') -> bytes:
    """Build a minimal SNMP v1 GetRequest PDU for sysDescr.0.

    This is a safe, read-only probe that queries the standard system
    description OID (1.3.6.1.2.1.1.1.0).
    """
    oid_val = bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
    oid_tlv = bytes([0x06, len(oid_val)]) + oid_val
    null_tlv = bytes([0x05, 0x00])
    varbind_content = oid_tlv + null_tlv
    varbind = bytes([0x30, len(varbind_content)]) + varbind_content
    vbl = bytes([0x30, len(varbind)]) + varbind
    req_id_tlv = bytes([0x02, 0x04, 0x00, 0x00, 0x12, 0x34])
    err_status = bytes([0x02, 0x01, 0x00])
    err_index = bytes([0x02, 0x01, 0x00])
    pdu_content = req_id_tlv + err_status + err_index + vbl
    pdu = bytes([0xA0, len(pdu_content)]) + pdu_content
    version_tlv = bytes([0x02, 0x01, 0x00])
    comm_bytes = community.encode('ascii')
    comm_tlv = bytes([0x04, len(comm_bytes)]) + comm_bytes
    msg_content = version_tlv + comm_tlv + pdu
    return bytes([0x30, len(msg_content)]) + msg_content


# Probe dispatch table: port → probe builder
_UDP_PROBE_BUILDERS: Dict[int, object] = {
    53:  _build_dns_probe,
    123: _build_ntp_probe,
    161: _build_snmp_probe,
    162: _build_snmp_probe,
}

# Generic probe payload used when no protocol-specific builder exists
_GENERIC_UDP_PROBE = b'\x00\x00'


def get_udp_probe(port: int) -> bytes:
    """Return a protocol-appropriate probe payload for *port*.

    Falls back to a minimal two-byte datagram for ports without a
    dedicated builder.  All probes are intentionally lightweight and
    non-intrusive (read-only or benign liveness checks).
    """
    builder = _UDP_PROBE_BUILDERS.get(port)
    if builder:
        return builder()  # type: ignore[call-arg]
    return _GENERIC_UDP_PROBE


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class UDPScanner:
    """UDP port scanner with protocol-aware probes and state classification.

    Parameters
    ----------
    target:      Host IP or hostname to scan.
    ports:       List of UDP port numbers to probe.  Defaults to
                 :data:`UDP_DEFAULT_PORTS` when ``None``.
    timeout:     Per-probe receive timeout in seconds (default 2.0).
    retries:     Total probe attempts per port (minimum 1, default 2).
    concurrency: Maximum parallel probe threads (default 30).
    """

    def __init__(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        timeout: float = 2.0,
        retries: int = 2,
        concurrency: int = 30,
    ):
        self.target = target
        self.ports = ports if ports is not None else list(UDP_DEFAULT_PORTS)
        self.timeout = max(0.1, float(timeout))
        self.retries = max(1, int(retries))
        self.concurrency = max(1, int(concurrency))

    def scan_port(self, port: int) -> Optional[Dict]:
        """Probe a single UDP port and return a result dict or ``None`` (closed).

        The result dict contains the keys ``port``, ``state``, ``service``,
        ``banner``, and ``protocol``.

        State values
        ------------
        ``open``          A response was received from the target.
        ``open|filtered`` No response — port could be open or filtered.
        ``None`` return   ICMP port-unreachable or unrecoverable error.
        """
        probe = get_udp_probe(port)
        service = UDP_SERVICE_NAMES.get(port, f'Unknown-{port}')

        for attempt in range(self.retries):
            sock: Optional[socket.socket] = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                sock.sendto(probe, (self.target, port))
                try:
                    response, _ = sock.recvfrom(1024)
                    sock.close()
                    banner = response[:100].decode('utf-8', errors='ignore').strip()
                    return {
                        'port': port,
                        'state': 'open',
                        'service': service,
                        'banner': banner,
                        'protocol': 'udp',
                    }
                except socket.timeout:
                    sock.close()
                    # No response — cannot distinguish open from filtered
                    return {
                        'port': port,
                        'state': 'open|filtered',
                        'service': service,
                        'banner': '',
                        'protocol': 'udp',
                    }
            except ConnectionRefusedError:
                # ICMP port-unreachable received — port is definitively closed
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass
                return None
            except OSError:
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass
                if attempt < self.retries - 1:
                    continue
                return None
        return None  # pragma: no cover

    def scan(self) -> List[Dict]:
        """Probe all configured UDP ports; return open/open|filtered results.

        Ports classified as ``closed`` (ICMP unreachable) are excluded from
        the returned list.  Results are sorted by port number.
        """
        results: List[Dict] = []

        if _HAS_THREADING:
            with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
                futures = {
                    executor.submit(self.scan_port, port): port
                    for port in self.ports
                }
                for future in as_completed(futures):
                    result = future.result()
                    if result is not None:
                        results.append(result)
        else:
            for port in self.ports:
                result = self.scan_port(port)
                if result is not None:
                    results.append(result)

        results.sort(key=lambda r: r['port'])
        return results
