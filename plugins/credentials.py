"""
Credential model for Vultron credentialed scanning (PR1).

Typed dataclasses for SSH, WinRM, and WMI credentials.  Credentials are
never logged or serialised with secret values — use :func:`redact_credential`
from :mod:`plugins.secrets` when including credential info in output.

Supported credential types
--------------------------
SSHCredential
    Username + password **or** private-key path (mutually exclusive at
    validation time).  Supports passphrase-protected keys.
WinRMCredential
    Username + password with optional Active Directory domain and transport
    hint (``http`` / ``https``).
WMICredential
    Username + password with optional Active Directory domain.

Credential validation
---------------------
Call :meth:`Credential.validate` before use.  It raises
:exc:`CredentialValidationError` if required fields are missing.

Config precedence (for :mod:`plugins.providers`)
-------------------------------------------------
1. Explicit inline ``Credential`` object passed by caller
2. Environment variables (``VULTRON_SSH_USER``, etc.)
3. JSON / TOML credential file specified via ``--cred-file``
"""

from __future__ import annotations

import abc
import os
from dataclasses import dataclass, field
from typing import Literal, Optional


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class CredentialValidationError(ValueError):
    """Raised when a credential object fails validation."""


# ---------------------------------------------------------------------------
# Base credential
# ---------------------------------------------------------------------------


@dataclass
class Credential(abc.ABC):
    """Abstract base for all credential types.

    Subclasses must implement :meth:`validate`.
    """

    #: Credential type tag — used for registry dispatch.
    credential_type: str = field(init=False)

    @abc.abstractmethod
    def validate(self) -> None:
        """Raise :exc:`CredentialValidationError` if the credential is invalid."""

    def redacted_summary(self) -> str:
        """Return a one-line human-readable summary with secrets redacted."""
        return f"<{self.__class__.__name__} credential (details redacted)>"


# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------


@dataclass
class SSHCredential(Credential):
    """SSH credential supporting password-auth or key-based auth.

    Parameters
    ----------
    username:
        SSH username (required).
    password:
        Cleartext password for password-based auth.  Leave ``None`` for
        key-based auth.
    key_path:
        Absolute path to the private-key file for key-based auth.  Leave
        ``None`` for password-based auth.
    passphrase:
        Optional passphrase protecting the private key.
    port:
        SSH port (default 22).
    """

    username: str = ""
    password: Optional[str] = None
    key_path: Optional[str] = None
    passphrase: Optional[str] = None
    port: int = 22

    def __post_init__(self) -> None:
        object.__setattr__(self, "credential_type", "ssh")

    def validate(self) -> None:
        if not self.username:
            raise CredentialValidationError("SSHCredential: 'username' is required")
        if self.password is None and self.key_path is None:
            raise CredentialValidationError(
                "SSHCredential: either 'password' or 'key_path' must be provided"
            )
        if self.password is not None and self.key_path is not None:
            raise CredentialValidationError(
                "SSHCredential: provide 'password' or 'key_path', not both"
            )
        if self.key_path is not None and not os.path.isfile(self.key_path):
            raise CredentialValidationError(
                f"SSHCredential: key_path '{self.key_path}' does not exist"
            )
        if not (1 <= self.port <= 65535):
            raise CredentialValidationError(
                f"SSHCredential: port {self.port} is out of range (1–65535)"
            )

    def redacted_summary(self) -> str:
        auth = "key" if self.key_path else "password"
        return f"SSHCredential(user={self.username!r}, auth={auth}, port={self.port})"


# ---------------------------------------------------------------------------
# WinRM
# ---------------------------------------------------------------------------


@dataclass
class WinRMCredential(Credential):
    """WinRM credential for Windows Remote Management.

    Parameters
    ----------
    username:
        Windows username (required).
    password:
        Cleartext password (required).
    domain:
        Optional Active Directory domain name.
    transport:
        WinRM transport scheme — ``'http'`` (port 5985) or ``'https'``
        (port 5986).  Defaults to ``'http'``.
    port:
        Override the default WinRM port.  ``None`` → derive from transport.
    """

    username: str = ""
    password: Optional[str] = None
    domain: Optional[str] = None
    transport: Literal["http", "https"] = "http"
    port: Optional[int] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "credential_type", "winrm")

    @property
    def effective_port(self) -> int:
        """Return the port to connect on (explicit override or transport default)."""
        if self.port is not None:
            return self.port
        return 5986 if self.transport == "https" else 5985

    def validate(self) -> None:
        if not self.username:
            raise CredentialValidationError("WinRMCredential: 'username' is required")
        if not self.password:
            raise CredentialValidationError("WinRMCredential: 'password' is required")
        if self.transport not in ("http", "https"):
            raise CredentialValidationError(
                f"WinRMCredential: transport must be 'http' or 'https', got {self.transport!r}"
            )
        if self.port is not None and not (1 <= self.port <= 65535):
            raise CredentialValidationError(
                f"WinRMCredential: port {self.port} is out of range (1–65535)"
            )

    def redacted_summary(self) -> str:
        domain_part = f"domain={self.domain!r}, " if self.domain else ""
        return (
            f"WinRMCredential(user={self.username!r}, "
            f"{domain_part}transport={self.transport!r}, "
            f"port={self.effective_port})"
        )


# ---------------------------------------------------------------------------
# WMI
# ---------------------------------------------------------------------------


@dataclass
class WMICredential(Credential):
    """WMI credential for Windows Management Instrumentation.

    Parameters
    ----------
    username:
        Windows username (required).
    password:
        Cleartext password (required).
    domain:
        Optional Active Directory domain name.
        Use ``'.'`` for local accounts.
    namespace:
        WMI namespace (default ``'root/cimv2'``).
    """

    username: str = ""
    password: Optional[str] = None
    domain: Optional[str] = None
    namespace: str = "root/cimv2"

    def __post_init__(self) -> None:
        object.__setattr__(self, "credential_type", "wmi")

    def validate(self) -> None:
        if not self.username:
            raise CredentialValidationError("WMICredential: 'username' is required")
        if not self.password:
            raise CredentialValidationError("WMICredential: 'password' is required")
        if not self.namespace:
            raise CredentialValidationError("WMICredential: 'namespace' must not be empty")

    def redacted_summary(self) -> str:
        domain_part = f"domain={self.domain!r}, " if self.domain else ""
        return (
            f"WMICredential(user={self.username!r}, "
            f"{domain_part}namespace={self.namespace!r})"
        )


# ---------------------------------------------------------------------------
# CredentialSet
# ---------------------------------------------------------------------------


@dataclass
class CredentialSet:
    """Container that holds up to one credential of each supported type.

    Attributes
    ----------
    ssh:
        SSH credential, or ``None`` if not configured.
    winrm:
        WinRM credential, or ``None`` if not configured.
    wmi:
        WMI credential, or ``None`` if not configured.
    """

    ssh: Optional[SSHCredential] = None
    winrm: Optional[WinRMCredential] = None
    wmi: Optional[WMICredential] = None

    def is_empty(self) -> bool:
        """Return ``True`` if no credentials have been configured."""
        return self.ssh is None and self.winrm is None and self.wmi is None

    def validate_all(self) -> None:
        """Validate every non-None credential.

        Raises :exc:`CredentialValidationError` on the first failure.
        """
        for cred in (self.ssh, self.winrm, self.wmi):
            if cred is not None:
                cred.validate()

    def redacted_summary(self) -> dict:
        """Return a secrets-safe summary dict suitable for logging/reporting."""
        return {
            "ssh": self.ssh.redacted_summary() if self.ssh else None,
            "winrm": self.winrm.redacted_summary() if self.winrm else None,
            "wmi": self.wmi.redacted_summary() if self.wmi else None,
        }
