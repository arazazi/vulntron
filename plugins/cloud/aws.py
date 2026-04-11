"""
AWS EC2 cloud metadata provider for Vultron PR7.

Fetches EC2 instance metadata (IDs, IPs, state, tags, VPC/subnet/SG context)
using the AWS SDK (boto3).  Credentials are resolved by the standard boto3
credential chain (environment variables, ``~/.aws/credentials``, IAM role,
etc.).

boto3 is an **optional** dependency.  If it is not installed the provider
reports as unavailable and returns an empty instance list rather than raising.
"""

from typing import List, Optional

from .base import CloudInstance, CloudProvider


class AWSProvider(CloudProvider):
    """Cloud metadata provider for AWS EC2.

    Parameters
    ----------
    region:
        AWS region to query (e.g. ``'us-east-1'``).  When ``None`` the
        value is taken from the ``AWS_DEFAULT_REGION`` environment variable
        or the active profile configuration.
    profile:
        AWS named profile from ``~/.aws/config`` / ``~/.aws/credentials``.
        When ``None`` the default credential chain is used.
    tag_include:
        Optional list of ``key=value`` tag filters.  Only instances that
        match **all** specified tag pairs are returned.
    tag_exclude:
        Optional list of ``key=value`` tag filters.  Instances that match
        **any** of these pairs are excluded from the results.
    """

    def __init__(
        self,
        region: Optional[str] = None,
        profile: Optional[str] = None,
        tag_include: Optional[List[str]] = None,
        tag_exclude: Optional[List[str]] = None,
    ) -> None:
        self.region = region
        self.profile = profile
        self.tag_include = self._parse_tag_filters(tag_include or [])
        self.tag_exclude = self._parse_tag_filters(tag_exclude or [])

    # ------------------------------------------------------------------
    # CloudProvider interface
    # ------------------------------------------------------------------

    @property
    def provider_name(self) -> str:
        return "aws"

    def is_available(self) -> bool:
        """Return ``True`` only when boto3 is importable."""
        try:
            import boto3  # noqa: F401
            return True
        except ImportError:
            return False

    def list_instances(self) -> List[CloudInstance]:
        """Return EC2 instances accessible with the configured credentials.

        Returns an empty list (without raising) if:
        - boto3 is not installed
        - credentials are absent / insufficient
        - the API call fails for any reason
        """
        try:
            import boto3
            import botocore.exceptions
        except ImportError:
            return []

        try:
            client = self._build_client(boto3)
            paginator = client.get_paginator("describe_instances")
            instances: List[CloudInstance] = []
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for inst_data in reservation.get("Instances", []):
                        inst = self._parse_instance(inst_data)
                        if self._passes_filters(inst):
                            instances.append(inst)
            return instances
        except Exception:
            # Credentials missing, permission denied, network error, etc.
            return []

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_client(self, boto3_mod):
        """Build and return an EC2 boto3 client."""
        kwargs = {}
        if self.region:
            kwargs["region_name"] = self.region
        if self.profile:
            session = boto3_mod.Session(profile_name=self.profile, **kwargs)
            return session.client("ec2")
        return boto3_mod.client("ec2", **kwargs)

    @staticmethod
    def _parse_instance(data: dict) -> CloudInstance:
        """Convert a raw EC2 instance dict to a :class:`CloudInstance`."""
        instance_id = data.get("InstanceId", "")
        region = data.get("Placement", {}).get("AvailabilityZone", "")[:-1] or ""
        state = data.get("State", {}).get("Name", "unknown")
        instance_type = data.get("InstanceType")
        vpc_id = data.get("VpcId")
        subnet_id = data.get("SubnetId")

        # Collect private IPs from all network interfaces
        private_ips: List[str] = []
        public_ips: List[str] = []
        for ni in data.get("NetworkInterfaces", []):
            for pa in ni.get("PrivateIpAddresses", []):
                pip = pa.get("PrivateIpAddress")
                if pip and pip not in private_ips:
                    private_ips.append(pip)
                assoc = pa.get("Association", {})
                pub = assoc.get("PublicIp")
                if pub and pub not in public_ips:
                    public_ips.append(pub)
        # Fallback to top-level fields if no network interfaces listed
        if not private_ips and data.get("PrivateIpAddress"):
            private_ips.append(data["PrivateIpAddress"])
        if not public_ips and data.get("PublicIpAddress"):
            public_ips.append(data["PublicIpAddress"])

        security_group_ids = [
            sg.get("GroupId", "") for sg in data.get("SecurityGroups", [])
        ]

        tags: dict = {}
        for tag in data.get("Tags", []):
            k = tag.get("Key", "")
            v = tag.get("Value", "")
            if k:
                tags[k] = v

        return CloudInstance(
            instance_id=instance_id,
            provider="aws",
            region=region,
            state=state,
            private_ips=private_ips,
            public_ips=public_ips,
            tags=tags,
            vpc_id=vpc_id,
            subnet_id=subnet_id,
            security_group_ids=security_group_ids,
            instance_type=instance_type,
        )

    @staticmethod
    def _parse_tag_filters(raw: List[str]) -> List[tuple]:
        """Parse ``['key=value', ...]`` into ``[('key', 'value'), ...]``.

        Entries without ``=`` are silently skipped.
        """
        result = []
        for item in raw:
            if "=" in item:
                k, _, v = item.partition("=")
                result.append((k.strip(), v.strip()))
        return result

    def _passes_filters(self, inst: CloudInstance) -> bool:
        """Return ``True`` if *inst* satisfies include/exclude tag filters."""
        # Include: all specified tags must be present with matching values
        for k, v in self.tag_include:
            if inst.tags.get(k) != v:
                return False
        # Exclude: none of the specified tags should match
        for k, v in self.tag_exclude:
            if inst.tags.get(k) == v:
                return False
        return True
