# Report schema

`analyze` writes a JSON object to `--report` with these keys:

- `decision`: `allow` or `deny`.
- `reason_codes`: array of strings, unique, stable order. Empty on allow.
- `edge`: object from the edge parse (`ok`, `method`, `path`, `http_version`, `headers`, `body_hex`, `consumed`, `error`).
- `origin`: the same shape from the origin parse of the *forwarded* byte range (see the rules).
- `forwarded_len`: number of bytes the edge would forward as the first request.
- `leftover_len`: remaining bytes after that range.
- `normalized`: on allow, a Latin-1 string (CRLF headers, no obs-fold, a single body framing header) that both parsers accept and agree on; on deny, `null`.

Unknown keys are ignored by the CLI. Do not omit the keys above.
