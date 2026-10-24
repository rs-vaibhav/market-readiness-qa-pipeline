"""
External Dataset Ingestor for the Market-Readiness QA Pipeline.

Provides utilities to fetch external datasets from REST APIs via HTTP,
parse flexible citation/reference formats into a normalized schema,
verify dataset integrity via hash comparison, and produce a structured
ingestion report — all without introducing dependencies beyond those
already present in requirements.txt (``httpx``).

Typical usage
-------------
From Python::

    from core.external_dataset_ingestor import ingest_from_curl
    report = ingest_from_curl("https://example.com/api/data",
                              headers={"Authorization": "Bearer TOKEN"})

From the command line::

    python -m core.external_dataset_ingestor --url https://example.com/api/data \\
        --header "Authorization: Bearer TOKEN"
"""

import argparse
import hashlib
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

import httpx


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_REQUEST_TIMEOUT: float = 10.0  # seconds

# Ordered list of top-level keys to probe for citation lists inside an API response
_CITATION_CONTAINER_KEYS: tuple[str, ...] = ("citations", "sources", "references", "results", "data")

# Ordered list of keys to probe for a hash value inside an API response
_HASH_KEYS: tuple[str, ...] = ("sha256", "hash", "checksum", "data_hash", "md5")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Citation:
    """Normalised representation of a single citation / source reference."""
    source: str = ""
    url: str = ""
    ref_id: str = ""
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Return the citation as a plain dictionary."""
        return asdict(self)


@dataclass
class HashVerification:
    """Result of comparing a hash embedded in an API response to a local file."""
    provided_hash: str = ""
    algorithm: str = ""
    local_hash: Optional[str] = None
    match: Optional[bool] = None
    status: str = "NO_HASH_IN_RESPONSE"  # VERIFIED | MISMATCH | NO_LOCAL_FILE | NO_HASH_IN_RESPONSE

    def to_dict(self) -> dict:
        """Return the verification result as a plain dictionary."""
        return asdict(self)


@dataclass
class IngestionReport:
    """Full structured output produced by :func:`ingest_from_curl`."""
    url: str = ""
    citations: list[dict] = field(default_factory=list)
    hash_verification: dict = field(default_factory=dict)
    raw_response: dict = field(default_factory=dict)
    ingestion_status: str = "FAILED"  # OK | PARTIAL | FAILED

    def to_dict(self) -> dict:
        """Return the full ingestion report as a plain dictionary."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def fetch_dataset_from_api(url: str, headers: Optional[dict] = None) -> dict:
    """Fetch a remote dataset endpoint and return the parsed JSON body.

    Parameters
    ----------
    url:
        Fully-qualified URL to GET.
    headers:
        Optional mapping of HTTP request headers (e.g. ``{"Authorization": "Bearer TOKEN"}``).

    Returns
    -------
    dict
        The parsed JSON response on success.
        On any failure the returned dict contains:
        ``{"error": "<description>", "raw": "<response text or empty string>"}``.

    Notes
    -----
    - A 10-second connect + read timeout is enforced.
    - HTTP status errors (4xx / 5xx) are caught and returned as structured errors.
    - JSON decode failures surface the raw response text so callers can inspect it.
    """
    effective_headers: dict = headers or {}
    try:
        with httpx.Client(timeout=_REQUEST_TIMEOUT) as client:
            response = client.get(url, headers=effective_headers)
            response.raise_for_status()
    except httpx.TimeoutException as exc:
        return {"error": f"Request timed out after {_REQUEST_TIMEOUT}s: {exc}", "raw": ""}
    except httpx.HTTPStatusError as exc:
        raw_text = exc.response.text if exc.response is not None else ""
        return {
            "error": f"HTTP {exc.response.status_code} error for URL {url}: {exc}",
            "raw": raw_text,
        }
    except httpx.RequestError as exc:
        return {"error": f"Network request error: {exc}", "raw": ""}

    raw_text = response.text
    try:
        return response.json()
    except Exception as exc:  # json.JSONDecodeError or similar
        return {"error": f"JSON decode failed: {exc}", "raw": raw_text}


def parse_citations(api_response: dict) -> list[dict]:
    """Extract and normalise citation records from a flexible API response shape.

    Supports three common response layouts:

    1. **Top-level list** – the response itself is a list of citation objects.
    2. **Named container** – citations live under a well-known key such as
       ``"citations"``, ``"sources"``, or ``"references"`` (checked in that order).
    3. **Flat object** – the entire response dict is treated as a single citation.

    Each extracted record is normalised to::

        {
            "source": str,   # "title", "name", "source", or ""
            "url":    str,   # "url", "link", "href", or ""
            "ref_id": str,   # "id", "ref_id", "doi", or ""
            "raw":    dict,  # original record as-is
        }

    Parameters
    ----------
    api_response:
        The raw dict returned by :func:`fetch_dataset_from_api`.

    Returns
    -------
    list[dict]
        A (possibly empty) list of normalised citation dicts.
    """
    if not isinstance(api_response, dict):
        return []

    # Locate the collection of raw citation records
    raw_items: list[Any] = []

    if isinstance(api_response, list):
        # Shouldn't happen given type hint, but guard anyway
        raw_items = api_response  # type: ignore[assignment]
    else:
        # Check well-known container keys first
        for key in _CITATION_CONTAINER_KEYS:
            candidate = api_response.get(key)
            if isinstance(candidate, list):
                raw_items = candidate
                break
        else:
            # Fall back: treat the entire response as a single-item collection
            raw_items = [api_response]

    return [_normalise_citation(item) for item in raw_items if isinstance(item, dict)]


def _normalise_citation(record: dict) -> dict:
    """Convert a raw citation dict into the canonical schema.

    Parameters
    ----------
    record:
        Arbitrary dict representing one citation/source record.

    Returns
    -------
    dict
        Normalised citation with ``source``, ``url``, ``ref_id``, and ``raw`` keys.
    """
    source = (
        record.get("title")
        or record.get("name")
        or record.get("source")
        or ""
    )
    url = (
        record.get("url")
        or record.get("link")
        or record.get("href")
        or ""
    )
    ref_id = (
        record.get("id")
        or record.get("ref_id")
        or record.get("doi")
        or ""
    )
    return Citation(
        source=str(source),
        url=str(url),
        ref_id=str(ref_id),
        raw=record,
    ).to_dict()


def verify_dataset_hash(
    api_response: dict,
    local_file_path: Optional[str] = None,
) -> dict:
    """Compare a hash declared in an API response against a local file.

    Hash extraction probes the following keys (in order):
    ``"sha256"``, ``"hash"``, ``"checksum"``, ``"data_hash"``, ``"md5"``.

    Parameters
    ----------
    api_response:
        The raw dict returned by :func:`fetch_dataset_from_api`.
    local_file_path:
        Optional path to a local file whose SHA-256 digest will be computed
        and compared against the hash found in the response.

    Returns
    -------
    dict
        A dict with the following keys:

        * ``provided_hash`` – the hash string found in the API response (or ``""``).
        * ``algorithm`` – the response key under which the hash was found (or ``""``).
        * ``local_hash`` – SHA-256 hex digest of the local file, or ``None``.
        * ``match`` – ``True`` / ``False`` / ``None`` (when comparison is not possible).
        * ``status`` –

          - ``"VERIFIED"``          hash found and local file matches.
          - ``"MISMATCH"``          hash found but local file does **not** match.
          - ``"NO_LOCAL_FILE"``     hash found but no local file was supplied / readable.
          - ``"NO_HASH_IN_RESPONSE"`` no recognisable hash key in the API response.
    """
    # Locate the hash in the API response
    provided_hash: str = ""
    algorithm: str = ""
    for key in _HASH_KEYS:
        candidate = api_response.get(key)
        if candidate and isinstance(candidate, str):
            provided_hash = candidate.strip()
            algorithm = key
            break

    if not provided_hash:
        return HashVerification(status="NO_HASH_IN_RESPONSE").to_dict()

    # Compute local hash if a path was given
    local_hash: Optional[str] = None
    if local_file_path:
        local_path = Path(local_file_path)
        if local_path.is_file():
            local_hash = _sha256_of_file(local_path)
        # else: file not found — local_hash stays None

    if local_hash is None:
        return HashVerification(
            provided_hash=provided_hash,
            algorithm=algorithm,
            local_hash=None,
            match=None,
            status="NO_LOCAL_FILE",
        ).to_dict()

    matches = provided_hash.lower() == local_hash.lower()
    return HashVerification(
        provided_hash=provided_hash,
        algorithm=algorithm,
        local_hash=local_hash,
        match=matches,
        status="VERIFIED" if matches else "MISMATCH",
    ).to_dict()


def _sha256_of_file(path: Path) -> str:
    """Compute the SHA-256 hex digest of a file, reading it in chunks.

    Parameters
    ----------
    path:
        Path to an existing, readable file.

    Returns
    -------
    str
        Lowercase hexadecimal SHA-256 digest.
    """
    digest = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def ingest_from_curl(
    url: str,
    headers: Optional[dict] = None,
    local_file_path: Optional[str] = None,
) -> dict:
    """Main entry point: fetch, parse, verify, and return a full ingestion report.

    Combines :func:`fetch_dataset_from_api`, :func:`parse_citations`, and
    :func:`verify_dataset_hash` into a single pipeline call.

    Parameters
    ----------
    url:
        API endpoint to GET.
    headers:
        Optional HTTP request headers forwarded verbatim to ``httpx``.
    local_file_path:
        Optional path to a local file used for hash verification.

    Returns
    -------
    dict
        An :class:`IngestionReport` serialised to a plain dict::

            {
                "url":               str,
                "citations":         list[dict],
                "hash_verification": dict,
                "raw_response":      dict,
                "ingestion_status":  "OK" | "PARTIAL" | "FAILED",
            }

        ``ingestion_status`` semantics:

        * ``"OK"``      – fetch succeeded and at least one citation was parsed.
        * ``"PARTIAL"`` – fetch succeeded but no citations could be extracted.
        * ``"FAILED"``  – the HTTP fetch itself failed (``"error"`` key present).
    """
    raw_response = fetch_dataset_from_api(url, headers=headers)

    # Determine ingestion status from the presence of an error key
    if "error" in raw_response:
        return IngestionReport(
            url=url,
            citations=[],
            hash_verification=HashVerification(status="NO_HASH_IN_RESPONSE").to_dict(),
            raw_response=raw_response,
            ingestion_status="FAILED",
        ).to_dict()

    citations = parse_citations(raw_response)
    hash_verification = verify_dataset_hash(raw_response, local_file_path=local_file_path)

    ingestion_status = "OK" if citations else "PARTIAL"

    return IngestionReport(
        url=url,
        citations=citations,
        hash_verification=hash_verification,
        raw_response=raw_response,
        ingestion_status=ingestion_status,
    ).to_dict()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _build_arg_parser() -> argparse.ArgumentParser:
    """Construct the argument parser for the CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="python -m core.external_dataset_ingestor",
        description=(
            "Fetch an external dataset API, parse citations, verify hashes, "
            "and print a structured JSON ingestion report."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap_dedent_example(),
    )
    parser.add_argument(
        "--url",
        required=True,
        metavar="URL",
        help="Fully-qualified URL of the dataset API endpoint to fetch.",
    )
    parser.add_argument(
        "--header",
        action="append",
        metavar="KEY:VALUE",
        dest="headers",
        default=[],
        help=(
            'HTTP header in "Key: Value" format. '
            "May be specified multiple times for multiple headers."
        ),
    )
    parser.add_argument(
        "--local-file",
        metavar="PATH",
        default=None,
        dest="local_file",
        help="Optional path to a local file for hash verification.",
    )
    return parser


def textwrap_dedent_example() -> str:
    """Return the CLI usage example shown in --help."""
    return (
        "Examples:\n"
        "  python -m core.external_dataset_ingestor --url https://httpbin.org/json\n"
        '  python -m core.external_dataset_ingestor --url https://api.example.com/data \\\n'
        '      --header "Authorization: Bearer TOKEN" \\\n'
        '      --header "Accept: application/json" \\\n'
        "      --local-file /path/to/downloaded/dataset.bin\n"
    )


def _parse_headers(raw_headers: list[str]) -> dict:
    """Convert a list of ``"Key: Value"`` strings into a dict.

    Parameters
    ----------
    raw_headers:
        Each element should be a string of the form ``"Header-Name: header value"``.
        Entries that do not contain ``:`` are silently skipped.

    Returns
    -------
    dict
        Mapping of header names to values.
    """
    result: dict = {}
    for entry in raw_headers:
        if ":" not in entry:
            print(
                f"[WARNING] Ignoring malformed --header argument (no ':' found): {entry!r}",
                file=sys.stderr,
            )
            continue
        key, _, value = entry.partition(":")
        result[key.strip()] = value.strip()
    return result


if __name__ == "__main__":
    parser = _build_arg_parser()
    args = parser.parse_args()

    headers = _parse_headers(args.headers)
    report = ingest_from_curl(
        url=args.url,
        headers=headers if headers else None,
        local_file_path=args.local_file,
    )

    print(json.dumps(report, indent=2, default=str))
