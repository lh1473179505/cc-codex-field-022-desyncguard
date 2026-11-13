"""Decide whether raw keepalive bytes are safe to forward edge -> origin.

The edge consumes a prefix of the input and forwards exactly those bytes,
unmodified, to the origin. Whatever is left stays on the connection and
would be parsed as the next request. This module reuses parse_edge and
parse_origin; it does not reimplement HTTP parsing.
"""

from __future__ import annotations

from typing import Any

from desyncguard.parse import ParseResult, parse_edge, parse_origin

# Reason codes are reported in this order when several match.
_FRAMING_ORDER = (
    "obs_fold",
    "lf_line",
    "te_cl",
    "cl_cl",
    "te_not_last",
    "te_unknown",
)
_LEFTOVER_ORDER = ("leftover_request", "leftover_bytes", "origin_reads_ahead")
_MISMATCH_ORDER = (
    "path_mismatch",
    "method_mismatch",
    "header_mismatch",
    "body_mismatch",
    "version_mismatch",
)

_FRAMING_HEADERS = ("content-length", "transfer-encoding")


def analyze(raw: bytes) -> dict[str, Any]:
    edge = parse_edge(raw)
    forwarded = raw[: edge.consumed] if edge.ok else b""
    origin = parse_origin(forwarded)
    leftover = raw[len(forwarded) :]

    framing = _framing_codes(raw, forwarded)
    leftover_codes = _leftover_codes(raw, edge, leftover) if edge.ok else set()
    mismatches = _mismatch_codes(edge, origin) if edge.ok and origin.ok else set()

    codes: list[str] = []

    def add(code: str | None) -> None:
        if code and code not in codes:
            codes.append(code)

    if not edge.ok:
        add(edge.error)
    for code in _FRAMING_ORDER:
        if code in framing:
            add(code)
    if edge.ok and not origin.ok:
        add(origin.error)
        add("origin_reject")
    for code in _LEFTOVER_ORDER:
        if code in leftover_codes:
            add(code)
    for code in _MISMATCH_ORDER:
        if code in mismatches:
            add(code)

    decision = "allow" if not codes else "deny"
    normalized: str | None = None
    if decision == "allow":
        normalized_bytes = _build_normalized(edge)
        if _verify_normalized(normalized_bytes, edge):
            normalized = normalized_bytes.decode("latin1")
        else:  # defensive: never emit a normalized request we cannot vouch for
            decision = "deny"
            codes = ["normalize_failed"]

    return {
        "decision": decision,
        "reason_codes": codes,
        "edge": edge.as_dict(),
        "origin": origin.as_dict(),
        "forwarded_len": len(forwarded),
        "leftover_len": len(raw) - len(forwarded),
        "normalized": normalized,
    }


def _scan_header_block(data: bytes) -> list[tuple[bytes, bytes]]:
    """Split the header block into (line, eol) pairs, stopping after the blank line."""
    lines: list[tuple[bytes, bytes]] = []
    i = 0
    while i < len(data):
        j = i
        while j < len(data) and data[j] not in (10, 13):
            j += 1
        if j >= len(data):
            lines.append((data[i:], b""))
            return lines
        if data[j] == 13 and j + 1 < len(data) and data[j + 1] == 10:
            eol = b"\r\n"
        elif data[j] == 10:
            eol = b"\n"
        else:
            lines.append((data[i:j], b""))
            return lines
        line = data[i:j]
        lines.append((line, eol))
        i = j + len(eol)
        if line == b"":
            return lines
    return lines


def _framing_codes(raw: bytes, forwarded: bytes) -> set[str]:
    """Spot ambiguous body framing directly in the raw bytes."""
    codes: set[str] = set()
    headers: list[tuple[bytes, bytes]] = []
    for line, _eol in _scan_header_block(raw)[1:]:
        if line == b"":
            break
        if line[:1] in (b" ", b"\t"):
            codes.add("obs_fold")
            continue
        if b":" in line:
            name, _, value = line.partition(b":")
            headers.append((name.strip().lower(), value.strip()))

    for _line, eol in _scan_header_block(forwarded):
        if eol == b"\n":
            codes.add("lf_line")
            break

    te_values = [v for n, v in headers if n == b"transfer-encoding"]
    cl_values = [v for n, v in headers if n == b"content-length"]
    if te_values and cl_values:
        codes.add("te_cl")
    if len(cl_values) > 1 and len(set(cl_values)) > 1:
        codes.add("cl_cl")
    codings: list[bytes] = []
    for value in te_values:
        for part in value.split(b","):
            token = part.split(b";", 1)[0].strip()
            if token:
                codings.append(token)
    if codings:
        if codings[-1].lower() != b"chunked":
            codes.add("te_not_last")
        if not any(c.lower() == b"chunked" for c in codings):
            codes.add("te_unknown")
    return codes


def _leftover_codes(raw: bytes, edge: ParseResult, leftover: bytes) -> set[str]:
    codes: set[str] = set()
    full = parse_origin(raw)
    if full.ok and full.consumed > edge.consumed:
        codes.add("origin_reads_ahead")
    if leftover:
        codes.add("leftover_bytes")
        if parse_edge(leftover).ok:
            codes.add("leftover_request")
    return codes


def _mismatch_codes(edge: ParseResult, origin: ParseResult) -> set[str]:
    codes: set[str] = set()
    if edge.method != origin.method:
        codes.add("method_mismatch")
    if edge.http_version != origin.http_version:
        codes.add("version_mismatch")
    if not _paths_agree(edge, origin):
        codes.add("path_mismatch")
    if _norm_headers(edge) != _norm_headers(origin):
        codes.add("header_mismatch")
    if edge.body != origin.body:
        codes.add("body_mismatch")
    return codes


def _norm_headers(res: ParseResult) -> dict[str, list[str]]:
    return {
        name: sorted(value.strip(" \t") for value in values)
        for name, values in res.header_map().items()
    }


def _paths_agree(edge: ParseResult, origin: ParseResult) -> bool:
    if edge.path != origin.path:
        return False
    for res in (edge, origin):
        if res.abs_form_host is not None:
            host_values = res.header_map().get("host") or []
            if not host_values:
                return False
            if _norm_host(res.abs_form_host) != _norm_host(host_values[0]):
                return False
    return True


def _norm_host(host: str) -> str:
    host = host.strip().lower()
    if host.startswith("["):  # IP-literal, keep as-is apart from case
        return host
    name, sep, port = host.rpartition(":")
    if sep and port in ("80", "443"):
        return name
    return host


def _build_normalized(edge: ParseResult) -> bytes:
    """Emit one CRLF request with a single Host and a single framing header."""
    lines = [f"{edge.method} {edge.path} HTTP/1.1"]
    host_kept = False
    for name, value in edge.headers:
        lname = name.lower()
        if lname in _FRAMING_HEADERS:
            continue
        if lname == "host":
            if host_kept:
                continue
            host_kept = True
        lines.append(f"{name}: {value}")
    lines.append(f"Content-Length: {len(edge.body)}")
    return "\r\n".join(lines).encode("latin1") + b"\r\n\r\n" + edge.body


def _verify_normalized(normalized: bytes, edge: ParseResult) -> bool:
    e = parse_edge(normalized)
    o = parse_origin(normalized)
    if not (e.ok and o.ok):
        return False
    if _mismatch_codes(e, o):
        return False
    return (
        e.method == edge.method
        and e.path == edge.path
        and e.body == edge.body
        and _kept_headers(e) == _kept_headers(edge)
    )


def _kept_headers(res: ParseResult) -> dict[str, list[str]]:
    return {
        name: values
        for name, values in _norm_headers(res).items()
        if name not in _FRAMING_HEADERS
    }
