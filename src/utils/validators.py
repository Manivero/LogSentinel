"""Input validation utilities.

These functions validate *structural* properties of user-supplied input
(paths, sizes, encodings, argument values) and raise typed exceptions on
failure. Content-level threat detection (prompt injection patterns) lives
in `src.analysis.sanitizer`, which builds on `src.utils.security`.
"""

from __future__ import annotations

from pathlib import Path

from src.core.exceptions import FileAccessError, FileEncodingError, FileTooLargeError

_SUPPORTED_EXPORT_FORMATS = {"json", "md", "markdown", "html", "csv"}


def validate_log_file_path(
    path: str | Path,
    *,
    allowed_roots: list[str] | None = None,
) -> Path:
    """Resolve and validate a user-supplied log file path.

    Ensures the path exists, is a regular file, is readable, and — if
    `allowed_roots` is non-empty — resides under one of those directories
    (defense against path traversal such as `../../etc/passwd`).

    Returns:
        The resolved, absolute `Path`.

    Raises:
        FileAccessError: If the path does not exist, is not a regular
            file, is not readable, or escapes the configured allowlist.
    """
    candidate = Path(path).expanduser()
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise FileAccessError(f"Path does not exist or cannot be resolved: {path}") from exc

    if not resolved.is_file():
        raise FileAccessError(f"Path is not a regular file: {resolved}")

    try:
        with resolved.open("rb"):
            pass
    except OSError as exc:
        raise FileAccessError(f"Path is not readable: {resolved}") from exc

    if allowed_roots:
        resolved_roots = [Path(root).expanduser().resolve() for root in allowed_roots]
        if not any(resolved.is_relative_to(root) for root in resolved_roots):
            raise FileAccessError(
                f"Path is outside the allowed log directories: {resolved}",
                details={"allowed_roots": [str(r) for r in resolved_roots]},
            )

    return resolved


def validate_file_size(path: Path, *, max_bytes: int) -> int:
    """Validate a file does not exceed `max_bytes`. Returns its size in bytes.

    Raises:
        FileTooLargeError: If the file exceeds the configured maximum.
    """
    size = path.stat().st_size
    if size > max_bytes:
        raise FileTooLargeError(
            f"File exceeds maximum allowed size: {path}",
            details={"size_bytes": size, "max_bytes": max_bytes},
        )
    return size


def validate_text_encoding(path: Path, *, allowed_encodings: list[str]) -> str:
    """Determine and validate the file's text encoding.

    Tries each allowed encoding in order and returns the first that decodes
    a sample of the file cleanly. This is a strict check (not a lossy
    `errors="replace"` detection) so binary files are reliably rejected.

    Raises:
        FileEncodingError: If no allowed encoding can decode the file, or
            the file appears to be binary.
    """
    sample_size = 1024 * 1024  # 1 MB is enough to detect encoding issues
    try:
        with path.open("rb") as fh:
            sample = fh.read(sample_size)
    except OSError as exc:
        raise FileEncodingError(f"Could not read file for encoding detection: {path}") from exc

    if b"\x00" in sample:
        raise FileEncodingError(f"File appears to be binary (contains NUL bytes): {path}")

    for encoding in allowed_encodings:
        try:
            sample.decode(encoding)
            return encoding
        except (UnicodeDecodeError, LookupError):
            continue

    raise FileEncodingError(
        f"File is not decodable with any allowed encoding: {path}",
        details={"allowed_encodings": allowed_encodings},
    )


def validate_export_formats(formats: str | list[str]) -> list[str]:
    """Normalize and validate a comma-separated or list `--format` value.

    Accepts `"json,md,html,csv"` or `["json", "html"]`; returns a
    de-duplicated, normalized list (e.g. `"markdown"` -> `"md"`).

    Raises:
        ValueError: If an unrecognized format is requested.
    """
    if isinstance(formats, str):
        candidates = [f.strip().lower() for f in formats.split(",") if f.strip()]
    else:
        candidates = [f.strip().lower() for f in formats if f.strip()]

    normalized: list[str] = []
    for fmt in candidates:
        if fmt not in _SUPPORTED_EXPORT_FORMATS:
            raise ValueError(
                f"Unsupported export format '{fmt}'. Supported: {sorted(_SUPPORTED_EXPORT_FORMATS)}"
            )
        canonical = "md" if fmt == "markdown" else fmt
        if canonical not in normalized:
            normalized.append(canonical)
    return normalized
