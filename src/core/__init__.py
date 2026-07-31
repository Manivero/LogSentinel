"""Core domain layer: configuration, data models, schemas, and exceptions.

Nothing in `src.core` imports from any other `src` subpackage — every other
package depends on `core`, never the reverse. This keeps the domain model
and configuration free of circular-import risk and makes `core` safely
importable from anywhere (including tooling scripts and tests) without
pulling in httpx, ChromaDB, or any other heavier dependency.
"""
