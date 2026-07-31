"""Cross-cutting utilities: logging, security, validation, and concurrency.

Depends only on `src.core`. Used by every other subsystem, so nothing in
this package may import from `src.ollama`, `src.parsing`, `src.detection`,
`src.analysis`, `src.knowledge`, `src.reporting`, or `src.metrics`.
"""
