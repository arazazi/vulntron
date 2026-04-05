"""
Secret masking and redaction helpers for Vultron (PR1).

This module centralises all secret handling so that credentials and other
sensitive values are **never** exposed in logs, reports, CLI output, or
serialised scan metadata.

Usage
-----
::

    from plugins.secrets import mask_secret, redact_dict, REDACTED

    safe_log_line = f"Connecting with password={mask_secret(password)}"
    # → "Connecting with password=***REDACTED***"

    safe_dict = redact_dict({"password": "s3cr3t", "host": "10.0.0.1"})
    # → {"password": "***REDACTED***", "host": "10.0.0.1"}
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Replacement token used everywhere a secret value must be hidden.
REDACTED = "***REDACTED***"

#: Keys whose values should always be redacted (case-insensitive).
_SENSITIVE_KEYS: frozenset = frozenset([
    "password",
    "passwd",
    "pass",
    "secret",
    "key",
    "private_key",
    "key_path",
    "passphrase",
    "token",
    "api_key",
    "credential",
    "credentials",
    "auth",
    "authorization",
    "access_key",
    "access_secret",
    "client_secret",
])

# Pattern that matches common secret-like inline assignments in strings
# e.g. "password=abc123", "key: 'mykey'"
_INLINE_SECRET_RE = re.compile(
    r"(?i)(password|passwd|pass|secret|key|token|api_key|passphrase)\s*[=:]\s*\S+",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------


def mask_secret(value: Optional[str]) -> str:
    """Return :data:`REDACTED` regardless of the input value.

    Parameters
    ----------
    value:
        The secret string to mask.  May be ``None``.

    Returns
    -------
    str
        Always ``'***REDACTED***'``.
    """
    return REDACTED  # intentionally ignores the input value


def is_sensitive_key(key: str) -> bool:
    """Return ``True`` if *key* is in the known sensitive key set.

    The comparison is case-insensitive.
    """
    return key.lower() in _SENSITIVE_KEYS


def redact_dict(
    d: Dict[str, Any],
    extra_keys: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Return a copy of *d* with sensitive values replaced by :data:`REDACTED`.

    Parameters
    ----------
    d:
        Input dictionary.  Values for keys matching :data:`_SENSITIVE_KEYS`
        (or *extra_keys*) are replaced.  Non-string values are replaced too.
    extra_keys:
        Optional additional key names to treat as sensitive (case-insensitive).

    Returns
    -------
    dict
        A shallow copy of *d* with secret values masked.  Nested dicts are
        **not** recursed into; use :func:`deep_redact_dict` for that.
    """
    extra_lower: frozenset = frozenset(k.lower() for k in (extra_keys or []))
    out: Dict[str, Any] = {}
    for k, v in d.items():
        if is_sensitive_key(k) or k.lower() in extra_lower:
            out[k] = REDACTED
        else:
            out[k] = v
    return out


def deep_redact_dict(
    d: Any,
    extra_keys: Optional[Sequence[str]] = None,
) -> Any:
    """Recursively redact sensitive values from a nested dict/list structure.

    Parameters
    ----------
    d:
        A ``dict``, ``list``, or scalar value.  Dicts are processed
        recursively; lists are iterated.  Scalars are returned unchanged.
    extra_keys:
        Additional key names to treat as sensitive.

    Returns
    -------
    Any
        A deep copy of *d* with all sensitive keys masked.
    """
    if isinstance(d, dict):
        extra_lower: frozenset = frozenset(k.lower() for k in (extra_keys or []))
        out: Dict[str, Any] = {}
        for k, v in d.items():
            if is_sensitive_key(k) or k.lower() in extra_lower:
                out[k] = REDACTED
            else:
                out[k] = deep_redact_dict(v, extra_keys)
        return out
    if isinstance(d, list):
        return [deep_redact_dict(item, extra_keys) for item in d]
    return d


def redact_string(text: str) -> str:
    """Replace inline secret assignments in a log string with :data:`REDACTED`.

    Handles patterns like ``password=abc123`` or ``key: 'mykey'``.

    Parameters
    ----------
    text:
        The log line or message to sanitise.

    Returns
    -------
    str
        The sanitised string.
    """
    return _INLINE_SECRET_RE.sub(lambda m: f"{m.group(1)}={REDACTED}", text)


def safe_format_exception(exc: BaseException) -> str:
    """Return a sanitised string representation of *exc*.

    Credential-like keywords in the exception message are redacted so that
    passwords embedded in connection strings do not leak into error logs.
    """
    raw = str(exc)
    return redact_string(raw)


# ---------------------------------------------------------------------------
# Credential-specific helpers
# ---------------------------------------------------------------------------


def credential_safe_repr(cred: Any) -> str:
    """Return a safe string representation of a credential object.

    If the object has a ``redacted_summary()`` method (as all
    :class:`~plugins.credentials.Credential` subclasses do), that is
    returned.  Otherwise a generic placeholder is used.
    """
    if hasattr(cred, "redacted_summary"):
        return cred.redacted_summary()
    return "<credential (details redacted)>"
