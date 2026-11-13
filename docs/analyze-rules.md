# Analyze rules

The edge and origin parsers already live in this repo. Reuse `parse_edge` and `parse_origin`. Do not reimplement HTTP parsing, and do not call an external proxy.

`inspect` shows what each parser sees on the *entire* input. `analyze` has to reason about a keepalive connection: the edge consumes a prefix, forwards exactly those raw bytes (no header rewrite, no recoding) to the origin, and keeps the leftover for the next request.

## Forwarded range

- If the edge parse fails, consume nothing (`forwarded_len = 0`, `leftover_len = len(input)`). Decision is `deny` with the edge `error` as a reason code (and `edge_reject` if you need a wrapper — prefer the parser's own error code).
- If the edge parse succeeds, `forwarded_len` is `edge.consumed` and the forwarded bytes are `input[:consumed]`. The origin is then run on that forwarded slice, not on the leftover.
- `leftover_len` is `len(input) - forwarded_len`.

## When to deny

A request is only `allow` when all of the following hold:

1. The edge parse succeeds.
2. The origin parse of the forwarded slice succeeds.
3. Edge and origin agree on `method`, `path` (see path rules), `http_version`, the header map (case-insensitive names, order ignored, values compared after ordinary LWS trim), and the exact body bytes.
4. There is no leftover that the origin, *if it were given the full original input*, would have treated as part of this same first request (body or trailer). If `parse_origin(full_input)` succeeds and its `consumed` is greater than the edge `consumed`, that is `origin_reads_ahead`.
5. If leftover is non-empty, it must not itself start an HTTP/1.x request line that the edge would accept. That is `leftover_request`. A leftover of only trailing padding is still not allowed in this lab: any leftover is `leftover_bytes`. The public policy is strict because a keepalive connection would otherwise start the next parse at an attacker-chosen offset.

If the origin parse of the forwarded slice fails, include the origin `error` code and also `origin_reject`.

Disagreement on body framing should also carry a more specific code when it applies (more than one may be present, list them in this order when several match):

- `obs_fold` — the raw input contains a folded header line (a line after the request line that starts with SP or HTAB).
- `lf_line` — any request/header/end-of-headers line in the forwarded range is terminated with a lone LF rather than CRLF.
- `te_cl` — both `Transfer-Encoding` and `Content-Length` are present on the edge view or in the raw header block.
- `cl_cl` — more than one `Content-Length` header is present and their trimmed values are not all identical.
- `te_not_last` — a `Transfer-Encoding` list is present and the last coding is not `chunked` (comparison is case-insensitive).
- `te_unknown` — a `Transfer-Encoding` is present but does not include `chunked`.
- `path_mismatch`, `method_mismatch`, `header_mismatch`, `body_mismatch`, `version_mismatch` — the two successful parses disagree on that field.

## Path rules

The parsers already expose `path` as the origin-form path plus query, or the absolute-form path they extracted. `http://host/x` and `/x` are the same path if the host in the absolute-form URI equals the `Host` header (case-insensitive host, ignore a default port). Otherwise `path_mismatch`.

## Normalized request

On allow, write a single HTTP/1.1 request that both parsers accept and agree on:

- Request line and headers end with CRLF, blank line is CRLFCRLF.
- No folded headers.
- A single `Host`.
- Exactly one body framing header: `Content-Length` with the decimal body length, unless the original accepted request used chunked framing and had no `Content-Length`; in that case keep a single `Transfer-Encoding: chunked` and the same chunked body bytes the parsers decoded *from*, or rewrite to an equivalent `Content-Length` framing of the decoded body. Either is fine if both parsers accept and agree on method, path, headers you kept, and decoded body.
- Do not add hop-by-hop headers that were not in the original.

## Exit codes

- `allow` → exit 0
- `deny` → exit 1
- unreadable input, or an implementation error that prevents a report → exit 2. If you can still write a deny report, prefer that and exit 1.

## Public fixtures

Run these with `python -m desyncguard analyze --raw FIXTURE --report /tmp/desync-report.json`:

- `fixtures/requests/ok-simple.raw` → allow
- `fixtures/requests/ok-post.raw` → allow
- `fixtures/requests/ok-chunked.raw` → allow
- `fixtures/requests/te-cl.raw` → deny, reason includes `te_cl`
- `fixtures/requests/cl-cl.raw` → deny, reason includes `cl_cl`
- `fixtures/requests/obs-fold.raw` → deny, reason includes `obs_fold`
- `fixtures/requests/lf-only.raw` → deny, reason includes `lf_line`
- `fixtures/requests/te-not-last.raw` → deny, reason includes `te_not_last`
