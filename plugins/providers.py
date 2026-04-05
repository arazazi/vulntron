"""
Credential provider abstraction for Vultron (PR1).

A credential *provider* is responsible for returning a
:class:`~plugins.credentials.CredentialSet` for a given target.  The
abstraction makes it straightforward to add Vault, KMS, or other secret-store
backends in later PRs without touching the scanning logic.

Built-in providers
------------------
InlineCredentialProvider
    Uses a :class:`~plugins.credentials.CredentialSet` passed directly at
    construction time.  Suitable for CLI / programmatic use.
EnvCredentialProvider
    Reads credentials from environment variables (see :ref:`env-vars`).
FileCredentialProvider
    Loads credentials from a JSON file (no passwords stored in plaintext
    in the repo — the file is supplied at runtime).
ChainedCredentialProvider
    Tries multiple providers in order and returns the first non-empty result.

.. _env-vars:

Environment variable reference
-------------------------------
SSH::

    VULTRON_SSH_USER        SSH username
    VULTRON_SSH_PASSWORD    SSH password (mutually exclusive with key)
    VULTRON_SSH_KEY_PATH    Path to SSH private key
    VULTRON_SSH_PASSPHRASE  Passphrase protecting the private key
    VULTRON_SSH_PORT        SSH port (default 22)

WinRM::

    VULTRON_WINRM_USER      WinRM username
    VULTRON_WINRM_PASSWORD  WinRM password
    VULTRON_WINRM_DOMAIN    Active Directory domain (optional)
    VULTRON_WINRM_TRANSPORT Transport: 'http' or 'https' (default 'http')
    VULTRON_WINRM_PORT      WinRM port override (optional)

WMI::

    VULTRON_WMI_USER        WMI username
    VULTRON_WMI_PASSWORD    WMI password
    VULTRON_WMI_DOMAIN      Active Directory domain (optional)
    VULTRON_WMI_NAMESPACE   WMI namespace (default 'root/cimv2')
"""

from __future__ import annotations

import abc
import json
import os
from typing import List, Optional

from .credentials import (
    CredentialSet,
    CredentialValidationError,
    SSHCredential,
    WinRMCredential,
    WMICredential,
)


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class CredentialProvider(abc.ABC):
    """Abstract credential provider interface.

    Implementations must override :meth:`get_credentials`.
    """

    @abc.abstractmethod
    def get_credentials(self, target: str = "") -> CredentialSet:
        """Return a :class:`~plugins.credentials.CredentialSet` for *target*.

        Parameters
        ----------
        target:
            Optional target host/IP.  Providers may use this to look up
            per-host credentials (e.g. from a Vault policy).  The default
            providers ignore it and return the same credentials for all hosts.

        Returns
        -------
        CredentialSet
            A (potentially empty) credential set.  Never raises — return an
            empty :class:`~plugins.credentials.CredentialSet` when no
            credentials are available.
        """


# ---------------------------------------------------------------------------
# InlineCredentialProvider
# ---------------------------------------------------------------------------


class InlineCredentialProvider(CredentialProvider):
    """Provider backed by an explicit :class:`~plugins.credentials.CredentialSet`.

    This is the default provider used when credentials are supplied directly
    via CLI arguments or programmatic calls.

    Parameters
    ----------
    credential_set:
        The pre-built credential set to return for every target.
    """

    def __init__(self, credential_set: CredentialSet) -> None:
        self._cred_set = credential_set

    def get_credentials(self, target: str = "") -> CredentialSet:
        return self._cred_set


# ---------------------------------------------------------------------------
# EnvCredentialProvider
# ---------------------------------------------------------------------------


class EnvCredentialProvider(CredentialProvider):
    """Provider that reads credentials from environment variables.

    See the module docstring for the full list of supported environment
    variables.  Returns an empty :class:`~plugins.credentials.CredentialSet`
    if none of the expected variables are set.
    """

    def get_credentials(self, target: str = "") -> CredentialSet:
        ssh = self._load_ssh()
        winrm = self._load_winrm()
        wmi = self._load_wmi()
        return CredentialSet(ssh=ssh, winrm=winrm, wmi=wmi)

    @staticmethod
    def _load_ssh() -> Optional[SSHCredential]:
        user = os.environ.get("VULTRON_SSH_USER", "").strip()
        if not user:
            return None
        password = os.environ.get("VULTRON_SSH_PASSWORD") or None
        key_path = os.environ.get("VULTRON_SSH_KEY_PATH") or None
        passphrase = os.environ.get("VULTRON_SSH_PASSPHRASE") or None
        port_str = os.environ.get("VULTRON_SSH_PORT", "22")
        try:
            port = int(port_str)
        except ValueError:
            port = 22
        return SSHCredential(
            username=user,
            password=password,
            key_path=key_path,
            passphrase=passphrase,
            port=port,
        )

    @staticmethod
    def _load_winrm() -> Optional[WinRMCredential]:
        user = os.environ.get("VULTRON_WINRM_USER", "").strip()
        if not user:
            return None
        password = os.environ.get("VULTRON_WINRM_PASSWORD") or None
        domain = os.environ.get("VULTRON_WINRM_DOMAIN") or None
        transport = os.environ.get("VULTRON_WINRM_TRANSPORT", "http").lower()
        if transport not in ("http", "https"):
            transport = "http"
        port_str = os.environ.get("VULTRON_WINRM_PORT", "").strip()
        port: Optional[int] = None
        if port_str:
            try:
                port = int(port_str)
            except ValueError:
                pass
        return WinRMCredential(
            username=user,
            password=password,
            domain=domain,
            transport=transport,  # type: ignore[arg-type]
            port=port,
        )

    @staticmethod
    def _load_wmi() -> Optional[WMICredential]:
        user = os.environ.get("VULTRON_WMI_USER", "").strip()
        if not user:
            return None
        password = os.environ.get("VULTRON_WMI_PASSWORD") or None
        domain = os.environ.get("VULTRON_WMI_DOMAIN") or None
        namespace = os.environ.get("VULTRON_WMI_NAMESPACE", "root/cimv2").strip() or "root/cimv2"
        return WMICredential(
            username=user,
            password=password,
            domain=domain,
            namespace=namespace,
        )


# ---------------------------------------------------------------------------
# FileCredentialProvider
# ---------------------------------------------------------------------------


class FileCredentialProvider(CredentialProvider):
    """Provider that loads credentials from a JSON file.

    The JSON file must **not** be committed to version control.  Use
    placeholder values in any example / documentation files.

    Expected JSON structure::

        {
            "ssh": {
                "username": "scanuser",
                "password": "<your-ssh-password>",
                "port": 22
            },
            "winrm": {
                "username": "Administrator",
                "password": "<your-winrm-password>",
                "domain": "CORP",
                "transport": "http"
            },
            "wmi": {
                "username": "Administrator",
                "password": "<your-wmi-password>",
                "domain": "CORP"
            }
        }

    All top-level keys (``ssh``, ``winrm``, ``wmi``) are optional.

    Parameters
    ----------
    path:
        Absolute or relative path to the credential JSON file.
    """

    def __init__(self, path: str) -> None:
        self._path = path

    def get_credentials(self, target: str = "") -> CredentialSet:
        try:
            with open(self._path, encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            return CredentialSet()
        except (OSError, json.JSONDecodeError):
            return CredentialSet()

        if not isinstance(data, dict):
            return CredentialSet()

        ssh = self._parse_ssh(data.get("ssh"))
        winrm = self._parse_winrm(data.get("winrm"))
        wmi = self._parse_wmi(data.get("wmi"))
        return CredentialSet(ssh=ssh, winrm=winrm, wmi=wmi)

    @staticmethod
    def _parse_ssh(d: object) -> Optional[SSHCredential]:
        if not isinstance(d, dict):
            return None
        user = str(d.get("username", "")).strip()
        if not user:
            return None
        port_raw = d.get("port", 22)
        try:
            port = int(port_raw)
        except (TypeError, ValueError):
            port = 22
        return SSHCredential(
            username=user,
            password=d.get("password") or None,
            key_path=d.get("key_path") or None,
            passphrase=d.get("passphrase") or None,
            port=port,
        )

    @staticmethod
    def _parse_winrm(d: object) -> Optional[WinRMCredential]:
        if not isinstance(d, dict):
            return None
        user = str(d.get("username", "")).strip()
        if not user:
            return None
        transport = str(d.get("transport", "http")).lower()
        if transport not in ("http", "https"):
            transport = "http"
        port_raw = d.get("port")
        port: Optional[int] = None
        if port_raw is not None:
            try:
                port = int(port_raw)
            except (TypeError, ValueError):
                pass
        return WinRMCredential(
            username=user,
            password=d.get("password") or None,
            domain=d.get("domain") or None,
            transport=transport,  # type: ignore[arg-type]
            port=port,
        )

    @staticmethod
    def _parse_wmi(d: object) -> Optional[WMICredential]:
        if not isinstance(d, dict):
            return None
        user = str(d.get("username", "")).strip()
        if not user:
            return None
        namespace = str(d.get("namespace", "root/cimv2")).strip() or "root/cimv2"
        return WMICredential(
            username=user,
            password=d.get("password") or None,
            domain=d.get("domain") or None,
            namespace=namespace,
        )


# ---------------------------------------------------------------------------
# ChainedCredentialProvider
# ---------------------------------------------------------------------------


class ChainedCredentialProvider(CredentialProvider):
    """Try multiple providers in order; return the first non-empty result.

    This is useful for a fallback chain such as:
    *inline args → env vars → credential file*.

    Parameters
    ----------
    providers:
        Ordered sequence of :class:`CredentialProvider` instances.
    """

    def __init__(self, providers: List[CredentialProvider]) -> None:
        self._providers = list(providers)

    def get_credentials(self, target: str = "") -> CredentialSet:
        for provider in self._providers:
            cred_set = provider.get_credentials(target)
            if not cred_set.is_empty():
                return cred_set
        return CredentialSet()


# ---------------------------------------------------------------------------
# Factory helper
# ---------------------------------------------------------------------------


def build_default_provider(
    inline: Optional[CredentialSet] = None,
    cred_file: Optional[str] = None,
) -> CredentialProvider:
    """Build the default chained provider for CLI/config usage.

    Chain order:
    1. Inline credential set (if provided)
    2. Environment variables
    3. Credential file (if path provided)

    Parameters
    ----------
    inline:
        An explicit :class:`~plugins.credentials.CredentialSet`, e.g.
        built from CLI arguments.  ``None`` to skip.
    cred_file:
        Path to a JSON credential file.  ``None`` to skip.

    Returns
    -------
    CredentialProvider
        A :class:`ChainedCredentialProvider` wrapping all configured sources.
    """
    providers: List[CredentialProvider] = []
    if inline is not None and not inline.is_empty():
        providers.append(InlineCredentialProvider(inline))
    providers.append(EnvCredentialProvider())
    if cred_file:
        providers.append(FileCredentialProvider(cred_file))
    return ChainedCredentialProvider(providers)
