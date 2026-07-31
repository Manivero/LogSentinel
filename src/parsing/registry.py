"""Parser registration system.

A small, dependency-free registry that decouples "which parser classes
exist" from "which one should handle this file" (that decision lives in
`src.parsing.factory`). New parsers plug in by subclassing `BaseParser`
and decorating with `@register_parser` — no other code needs to change,
which is what makes this a true plugin system rather than a hardcoded
if/elif chain. See ADR-0002.
"""

from __future__ import annotations

from src.core.exceptions import ConfigurationError
from src.parsing.base_parser import BaseParser


class ParserRegistry:
    """Holds the set of known parser classes, keyed by their `name`."""

    def __init__(self) -> None:
        self._parsers: dict[str, type[BaseParser]] = {}

    def register(self, parser_cls: type[BaseParser]) -> type[BaseParser]:
        """Register `parser_cls`. Returns it unchanged, so this doubles as a decorator.

        Raises:
            ConfigurationError: If `parser_cls.name` is already registered
                to a *different* class (re-registering the same class,
                e.g. from a module imported twice, is a harmless no-op).
        """
        existing = self._parsers.get(parser_cls.name)
        if existing is not None and existing is not parser_cls:
            raise ConfigurationError(
                f"Parser name '{parser_cls.name}' is already registered to "
                f"{existing.__qualname__}; cannot also register {parser_cls.__qualname__}."
            )
        self._parsers[parser_cls.name] = parser_cls
        return parser_cls

    def unregister(self, name: str) -> None:
        self._parsers.pop(name, None)

    def get(self, name: str) -> type[BaseParser] | None:
        return self._parsers.get(name)

    def all(self) -> list[type[BaseParser]]:
        """All registered parser classes, in registration order."""
        return list(self._parsers.values())

    def competitive(self) -> list[type[BaseParser]]:
        """Registered parsers that participate in confidence-based ranking
        (excludes fallback parsers such as the generic line parser)."""
        return [p for p in self._parsers.values() if not p.is_fallback]

    def fallback(self) -> type[BaseParser] | None:
        """The first registered parser marked `is_fallback = True`, if any."""
        for parser_cls in self._parsers.values():
            if parser_cls.is_fallback:
                return parser_cls
        return None


#: Process-wide default registry. Built-in parsers register into this at
#: import time (see `src.parsing.parsers`); `ParserFactory` defaults to it
#: but accepts a different registry instance for testing/isolation.
default_registry = ParserRegistry()


def register_parser(parser_cls: type[BaseParser]) -> type[BaseParser]:
    """Decorator registering `parser_cls` into `default_registry`."""
    return default_registry.register(parser_cls)
