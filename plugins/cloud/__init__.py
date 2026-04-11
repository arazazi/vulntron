"""
Cloud provider framework for Vultron PR7.

Public API
----------
CloudInstance       Normalised representation of a cloud compute instance.
CloudProvider       Abstract base class for cloud metadata providers.
AWSProvider         AWS EC2 provider implementation.
CloudCorrelator     Correlate scan assets with cloud instances via IP lookup.
"""

from .base import CloudInstance, CloudProvider
from .aws import AWSProvider
from .correlator import CloudCorrelator

__all__ = [
    "CloudInstance",
    "CloudProvider",
    "AWSProvider",
    "CloudCorrelator",
]
