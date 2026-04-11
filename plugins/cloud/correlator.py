"""
Cloud-to-asset correlation logic for Vultron PR7.

:class:`CloudCorrelator` takes a list of :class:`~plugins.cloud.base.CloudInstance`
objects and matches them against :class:`~plugins.inventory.AssetRecord` objects
using IP address comparison as the primary key.

Matching strategy (in priority order)
--------------------------------------
1. Asset ``ip`` vs. instance ``private_ips`` (most reliable in internal scans).
2. Asset ``ip`` vs. instance ``public_ips`` (useful for edge/internet-facing scans).

When a match is found the correlator attaches the cloud metadata fields to the
asset record **without overwriting** any existing scan-derived hostname or label.
"""

from typing import Dict, List, Optional

from .base import CloudInstance


class CloudCorrelator:
    """Match scan-discovered assets to cloud instances via IP lookup.

    Parameters
    ----------
    instances:
        List of :class:`CloudInstance` objects to correlate against.
    """

    def __init__(self, instances: List[CloudInstance]) -> None:
        self._instances = list(instances)
        # Build fast IP → instance lookup tables
        self._by_private_ip: Dict[str, CloudInstance] = {}
        self._by_public_ip: Dict[str, CloudInstance] = {}
        for inst in instances:
            for ip in inst.private_ips:
                if ip not in self._by_private_ip:
                    self._by_private_ip[ip] = inst
            for ip in inst.public_ips:
                if ip not in self._by_public_ip:
                    self._by_public_ip[ip] = inst

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def find_match(self, ip: Optional[str]) -> Optional[CloudInstance]:
        """Return the first cloud instance whose IPs include *ip*, or ``None``.

        Private IPs are checked before public IPs.

        Parameters
        ----------
        ip:
            The IP address to look up.  When ``None`` the method returns
            ``None`` immediately.
        """
        if not ip:
            return None
        return self._by_private_ip.get(ip) or self._by_public_ip.get(ip)

    def enrich_asset(self, asset) -> bool:
        """Attach cloud metadata to *asset* if a matching instance is found.

        Populates ``cloud_provider``, ``cloud_instance_id``,
        ``cloud_region``, ``cloud_instance_state``, ``cloud_instance_type``,
        ``cloud_tags``, ``cloud_vpc_id``, ``cloud_subnet_id``, and
        ``cloud_security_group_ids`` on the asset record.

        Existing user-provided hostnames and labels on the asset are
        **never overwritten**.

        Parameters
        ----------
        asset:
            An :class:`~plugins.inventory.AssetRecord` instance.

        Returns
        -------
        bool
            ``True`` if a matching cloud instance was found and metadata was
            attached; ``False`` otherwise.
        """
        inst = self.find_match(asset.ip)
        if inst is None:
            return False

        asset.cloud_provider = inst.provider
        asset.cloud_instance_id = inst.instance_id
        asset.cloud_region = inst.region
        asset.cloud_instance_state = inst.state
        asset.cloud_instance_type = inst.instance_type
        asset.cloud_tags = dict(inst.tags)
        asset.cloud_vpc_id = inst.vpc_id
        asset.cloud_subnet_id = inst.subnet_id
        asset.cloud_security_group_ids = list(inst.security_group_ids)
        asset.add_source("cloud-aws")
        return True

    @property
    def instance_count(self) -> int:
        """Number of cloud instances available for correlation."""
        return len(self._instances)
