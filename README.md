# desyncguard

A lab tool for spotting HTTP/1.1 request smuggling between an edge parser and an origin parser.

`python -m desyncguard inspect --raw fixtures/requests/ok-simple.raw` already prints what the edge parser and the origin parser each see. `analyze` is still a stub: it must decide whether the same bytes are safe to forward on a keepalive connection.

Standard library only. No Docker, no HTTP stacks, no third-party parsers.
