"""
Cloud provider abstraction for Vultron PR7.

Defines the :class:`CloudProvider` abstract base class and the
:class:`CloudInstance` data model shared by all provider implementations.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class CloudInstance:
    """Normalised representation of a single cloud compute instance.

    Attributes
    ----------
    instance_id:        Provider-native instance identifier (e.g. ``i-0abc1234``).
    provider:           Short provider label (e.g. ``aws``).
    region:             Provider region string (e.g. ``us-east-1``).
    state:              Instance lifecycle state (e.g. ``running``, ``stopped``).
    private_ips:        List of private IPv4 addresses associated with the instance.
    public_ips:         List of public IPv4 addresses associated with the instance.
    tags:               Key/value tag pairs attached to the instance.
    vpc_id:             VPC identifier, if available.
    subnet_id:          Subnet identifier, if available.
    security_group_ids: List of security group identifiers.
    instance_type:      Machine/instance type (e.g. ``t3.micro``).
    """

    instance_id: str
    provider: str
    region: str
    state: str
    private_ips: List[str] = field(default_factory=list)
    public_ips: List[str] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)
    vpc_id: Optional[str] = None
    subnet_id: Optional[str] = None
    security_group_ids: List[str] = field(default_factory=list)
    instance_type: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dict suitable for JSON output."""
        return {
            "instance_id": self.instance_id,
            "provider": self.provider,
            "region": self.region,
            "state": self.state,
            "private_ips": list(self.private_ips),
            "public_ips": list(self.public_ips),
            "tags": dict(self.tags),
            "vpc_id": self.vpc_id,
            "subnet_id": self.subnet_id,
            "security_group_ids": list(self.security_group_ids),
            "instance_type": self.instance_type,
        }


class CloudProvider(ABC):
    """Abstract base class for cloud metadata providers.

    Subclass this and implement :meth:`provider_name` and
    :meth:`list_instances` to add support for a new cloud provider.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Short lowercase provider label, e.g. ``'aws'``."""

    @abstractmethod
    def list_instances(self) -> List[CloudInstance]:
        """Fetch all accessible instances from this provider.

        Implementations must:
        - Return an empty list (not raise) when credentials are absent or
          the provider API is unreachable.
        - Never perform active network scanning; metadata retrieval only.
        """

    def is_available(self) -> bool:
        """Return ``True`` if the required SDK and credentials are present.

        The default implementation always returns ``True``; override to add
        SDK availability checks.
        """
        return True
