"""Auto-import all built-in check modules to trigger their registry registrations."""

from . import auth_probes, network, smb  # noqa: F401
