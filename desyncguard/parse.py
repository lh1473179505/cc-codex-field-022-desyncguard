"""Edge (lenient) and origin (strict) HTTP/1.1 request parsers.

These parsers are the source of truth for this lab. Analyze must reuse them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping


@dataclass
class ParseResult:
    ok: bool
    method: str | None = None
    path: str | None = None
    http_version: str | None = None
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    consumed: int = 0
    error: str | None = None
    # abs_form_host is set when the request-target was an absolute URI.
    abs_form_host: str | None = None

    def header_map(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for name, value in self.headers:
            out.setdefault(name.lower(), []).append(value)
        return out

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "method": self.method,
            "path": self.path,
            "http_version": self.http_version,
            "headers": [{"name": n, "value": v} for n, v in self.headers],
            "body_hex": self.body.hex(),
            "consumed": self.consumed,
            "error": self.error,
        }


def parse_edge(data: bytes) -> ParseResult:
    return _parse(data, strict=False)


def parse_origin(data: bytes) -> ParseResult:
    return _parse(data, strict=True)


def _parse(data: bytes, *, strict: bool) -> ParseResult:
    try:
        return _parse_inner(data, strict=strict)
    except _Fail as exc:
        return ParseResult(ok=False, consumed=0, error=str(exc))


class _Fail(Exception):
    pass


def _parse_inner(data: bytes, *, strict: bool) -> ParseResult:
    if not data:
        raise _Fail("empty")

    # Split into lines with awareness of CR LF vs LF. Keep offsets.
    lines, offsets, used_lf, used_crlf, fold_flags = _split_header_block(data, strict=strict)
    if not lines:
        raise _Fail("no_request_line")

    # Request line
    req = lines[0]
    if req.startswith(b" ") or req.startswith(b"\t"):
        raise _Fail("bad_request_line")
    try:
        method_b, target_b, version_b = req.split(b" ", 2)
    except ValueError as exc:
        raise _Fail("bad_request_line") from exc
    if not method_b or not target_b or not version_b:
        raise _Fail("bad_request_line")
    if strict and (b"\x00" in method_b or b"\x00" in target_b):
        raise _Fail("control_char")
    method = method_b.decode("ascii", "strict") if _is_ascii_token(method_b) else None
    if method is None:
        raise _Fail("bad_method")
    version = version_b.decode("ascii", "strict") if _is_ascii_token(version_b) or version_b.startswith(b"HTTP/") else None
    if version not in {"HTTP/1.0", "HTTP/1.1"}:
        # edge is slightly looser about HTTP/1.1 with trailing space already stripped
        raise _Fail("bad_version")

    path, abs_host = _target_to_path(target_b, strict=strict)

    headers: list[tuple[str, str]] = []
    i = 1
    while i < len(lines):
        raw = lines[i]
        if fold_flags[i]:
            if strict:
                raise _Fail("obs_fold")
            if not headers:
                raise _Fail("obs_fold")
            # append SP + trimmed fold text to previous value
            extra = raw.decode("latin1").strip()
            name, prev = headers[-1]
            headers[-1] = (name, (prev + " " + extra).strip())
            i += 1
            continue
        if b":" not in raw:
            raise _Fail("bad_header")
        name_b, val_b = raw.split(b":", 1)
        if strict and (name_b != name_b.strip() or not name_b):
            # no whitespace in the name, and name cannot be empty
            raise _Fail("bad_header")
        if not strict:
            name_b = name_b.strip()
        if not name_b or any(c in name_b for c in b" \t"):
            raise _Fail("bad_header")
        if any(c < 0x20 and c not in (9,) or c == 0x7F for c in name_b):
            raise _Fail("control_char")
        if strict and any(c < 0x20 and c not in (9,) or c == 0x7F for c in val_b):
            raise _Fail("control_char")
        name = name_b.decode("latin1")
        val = val_b.decode("latin1")
        if strict:
            val = val.strip()
        else:
            val = val.strip()
        headers.append((name, val))
        i += 1

    header_end = offsets["body_start"]
    body_start = header_end

    # Framing
    te_vals = [v for n, v in headers if n.lower() == "transfer-encoding"]
    cl_vals = [v for n, v in headers if n.lower() == "content-length"]
    te_codings = _split_te(te_vals)
    has_te = bool(te_codings)
    has_chunked = any(c.lower() == "chunked" for c in te_codings)
    has_cl = bool(cl_vals)

    if strict and used_lf:
        raise _Fail("lf_line")
    if strict and any(fold_flags):
        raise _Fail("obs_fold")

    if has_te and has_cl:
        if strict:
            raise _Fail("te_cl")
        # edge: Transfer-Encoding wins if chunked is present; else fall back to CL
        if has_chunked:
            body, consumed = _read_chunked(data, body_start, strict=False)
            return _ok(method, path, version, headers, body, consumed, abs_host)
        # unknown TE: fall back to first Content-Length
        length = _parse_cl(cl_vals[0], strict=False)
        end = body_start + length
        if end > len(data):
            raise _Fail("truncated_body")
        return _ok(method, path, version, headers, data[body_start:end], end, abs_host)

    if has_te:
        if not has_chunked:
            if strict:
                raise _Fail("te_unknown")
            # edge with unknown TE and no CL: empty body, headers only
            return _ok(method, path, version, headers, b"", body_start, abs_host)
        if strict and te_codings[-1].lower() != "chunked":
            raise _Fail("te_not_last")
        if not strict and te_codings[-1].lower() != "chunked" and has_chunked:
            # edge still tries to read chunked if the token appears anywhere
            pass
        body, consumed = _read_chunked(data, body_start, strict=strict)
        return _ok(method, path, version, headers, body, consumed, abs_host)

    if has_cl:
        if strict:
            nums = [_parse_cl(v, strict=True) for v in cl_vals]
            if len(set(nums)) != 1:
                raise _Fail("cl_cl")
            length = nums[0]
        else:
            length = _parse_cl(cl_vals[0], strict=False)
        end = body_start + length
        if end > len(data):
            raise _Fail("truncated_body")
        return _ok(method, path, version, headers, data[body_start:end], end, abs_host)

    # no body framing: empty body, consumed is header end
    return _ok(method, path, version, headers, b"", body_start, abs_host)


def _ok(method, path, version, headers, body, consumed, abs_host) -> ParseResult:
    return ParseResult(
        ok=True,
        method=method,
        path=path,
        http_version=version,
        headers=headers,
        body=body,
        consumed=consumed,
        abs_form_host=abs_host,
    )


def _split_header_block(data: bytes, *, strict: bool):
    """Return header lines (without EOLs), start offsets, flags."""
    lines: list[bytes] = []
    fold_flags: list[bool] = []
    used_lf = False
    used_crlf = False
    i = 0
    body_start = None
    while i <= len(data):
        # find next eol
        if i >= len(data):
            raise _Fail("truncated_headers")
        j = i
        while j < len(data) and data[j] not in (10, 13):
            j += 1
        if j >= len(data):
            raise _Fail("truncated_headers")
        if data[j] == 13:
            if j + 1 < len(data) and data[j + 1] == 10:
                eol_len = 2
                used_crlf = True
            else:
                raise _Fail("bad_cr")
        else:
            # lone LF
            eol_len = 1
            used_lf = True
            if strict:
                # still record the line so the caller can mention lf_line, but
                # we raise after reconstructing if headers end, via used_lf.
                pass
        line = data[i:j]
        if line == b"":
            # end of headers
            body_start = j + eol_len
            break
        is_fold = line.startswith(b" ") or line.startswith(b"\t")
        lines.append(line)
        fold_flags.append(is_fold)
        i = j + eol_len
    if body_start is None:
        raise _Fail("truncated_headers")
    return lines, {"body_start": body_start}, used_lf, used_crlf, fold_flags


def _is_ascii_token(b: bytes) -> bool:
    if not b:
        return False
    for c in b:
        if c <= 32 or c >= 127 or c in b"()<>@,;:\\\"/[]?={}":
            return False
    return True


def _target_to_path(target: bytes, *, strict: bool) -> tuple[str, str | None]:
    if target == b"*":
        return "*", None
    try:
        text = target.decode("ascii")
    except UnicodeDecodeError as exc:
        raise _Fail("bad_target") from exc
    if text.startswith("http://") or text.startswith("https://"):
        # very small absolute-form parser
        rest = text.split("://", 1)[1]
        if "/" in rest:
            host, path = rest.split("/", 1)
            path = "/" + path
        else:
            host, path = rest, "/"
        if "@" in host:
            raise _Fail("bad_target")
        # strip default ports later in compare; keep raw host here
        return path, host
    if not text.startswith("/"):
        # origin-form must start with / ; authority-form only for CONNECT, not used here
        if strict:
            raise _Fail("bad_target")
        if text.startswith("http"):
            raise _Fail("bad_target")
        # edge still rejects authority-form for non-CONNECT
        raise _Fail("bad_target")
    return text, None


def _split_te(values: list[str]) -> list[str]:
    out: list[str] = []
    for v in values:
        for part in v.split(","):
            token = part.split(";", 1)[0].strip()
            if token:
                out.append(token)
    return out


def _parse_cl(value: str, *, strict: bool) -> int:
    s = value.strip()
    if not s or any(c not in "0123456789" for c in s):
        raise _Fail("bad_cl")
    if strict and (len(s) > 1 and s.startswith("0")):
        raise _Fail("bad_cl")
    try:
        n = int(s)
    except ValueError as exc:
        raise _Fail("bad_cl") from exc
    if n < 0:
        raise _Fail("bad_cl")
    return n


def _read_chunked(data: bytes, start: int, *, strict: bool) -> tuple[bytes, int]:
    i = start
    parts: list[bytes] = []
    while True:
        # size line
        eol = _find_eol(data, i, strict=strict)
        if eol is None:
            raise _Fail("truncated_chunk")
        line, next_i = eol
        size_tok = line.split(b";", 1)[0].strip()
        if not size_tok:
            raise _Fail("bad_chunk_size")
        try:
            size = int(size_tok, 16)
        except ValueError as exc:
            raise _Fail("bad_chunk_size") from exc
        if size < 0:
            raise _Fail("bad_chunk_size")
        if strict and (size_tok.startswith(b"+") or size_tok.startswith(b"-")):
            raise _Fail("bad_chunk_size")
        i = next_i
        if size == 0:
            # trailers until empty line
            while True:
                eol = _find_eol(data, i, strict=strict)
                if eol is None:
                    raise _Fail("truncated_trailer")
                line, next_i = eol
                i = next_i
                if line == b"":
                    return b"".join(parts), i
                if strict and (b":" not in line):
                    raise _Fail("bad_trailer")
            # unreachable
        end = i + size
        if end > len(data):
            raise _Fail("truncated_chunk")
        parts.append(data[i:end])
        i = end
        eol = _find_eol(data, i, strict=strict)
        if eol is None:
            raise _Fail("truncated_chunk")
        line, next_i = eol
        if line != b"":
            raise _Fail("bad_chunk_data")
        i = next_i


def _find_eol(data: bytes, i: int, *, strict: bool) -> tuple[bytes, int] | None:
    j = i
    while j < len(data) and data[j] not in (10, 13):
        j += 1
    if j >= len(data):
        return None
    if data[j] == 13:
        if j + 1 < len(data) and data[j + 1] == 10:
            return data[i:j], j + 2
        return None
    if strict:
        # lone LF is not a valid chunk line ending in origin
        raise _Fail("lf_line")
    return data[i:j], j + 1
