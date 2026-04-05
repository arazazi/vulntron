"""
Global check registry for Vultron plugin checks.

Checks are registered by decorating a :class:`~plugins.base.BaseCheck`
subclass with :meth:`CheckRegistry.register` (or calling it explicitly).
The registry maps ``check_id`` strings to check classes and supports
discovery by port number and service name.

Typical usage
-------------
::

    # Register a check (usually done via the decorator):
    @CheckRegistry.register
    class MyCheck(BaseCheck):
        check_id = 'MY-001'
        ...

    # Discover checks for a given port:
    checks = CheckRegistry.checks_for_port(445, service='SMB')
    for check_cls in checks:
        findings = check_cls().run(target, port)
"""

from typing import Dict, List, Optional, Type

from .base import BaseCheck


class CheckRegistry:
    """Global registry mapping ``check_id`` → :class:`~plugins.base.BaseCheck` subclass.

    This is a class-level (singleton) registry; all state lives on the class
    itself so there is no need to instantiate :class:`CheckRegistry`.
    """

    _checks: Dict[str, Type[BaseCheck]] = {}

    @classmethod
    def register(cls, check_cls: Type[BaseCheck]) -> Type[BaseCheck]:
        """Register *check_cls* and return it unchanged.

        Can be used as a plain decorator::

            @CheckRegistry.register
            class MyCheck(BaseCheck):
                ...

        Or called explicitly::

            CheckRegistry.register(MyCheck)

        Raises
        ------
        ValueError
            If *check_cls* does not define a non-empty ``check_id``.
        """
        if not check_cls.check_id:
            raise ValueError(
                f"Check class {check_cls.__name__!r} must define a non-empty check_id"
            )
        cls._checks[check_cls.check_id] = check_cls
        return check_cls

    @classmethod
    def get(cls, check_id: str) -> Optional[Type[BaseCheck]]:
        """Return the registered check class for *check_id*, or ``None``."""
        return cls._checks.get(check_id)

    @classmethod
    def all_checks(cls) -> List[Type[BaseCheck]]:
        """Return all registered check classes in registration order."""
        return list(cls._checks.values())

    @classmethod
    def checks_for_port(cls, port: int, service: str = "") -> List[Type[BaseCheck]]:
        """Return checks applicable to the given *port* and/or *service*.

        A check is included when *port* appears in its ``required_ports``
        **or** *service* (case-insensitive) matches any entry in its
        ``service_matchers``.

        Parameters
        ----------
        port:
            TCP/UDP port number.
        service:
            Optional service name string (e.g. ``'SMB'``).
        """
        results: List[Type[BaseCheck]] = []
        svc_upper = service.upper() if service else ""
        for check_cls in cls._checks.values():
            port_match = port in (check_cls.required_ports or [])
            svc_match = bool(
                svc_upper
                and any(
                    svc_upper == m.upper()
                    for m in (check_cls.service_matchers or [])
                )
            )
            if port_match or svc_match:
                results.append(check_cls)
        return results

    @classmethod
    def clear(cls) -> None:
        """Remove all registered checks.

        Intended for use in tests to achieve a clean registry state.
        """
        cls._checks.clear()
