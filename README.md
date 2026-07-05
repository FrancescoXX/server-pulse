# Pulse — web server score

Paste a URL, get a 0–100 score for the web server behind it.

![Node.js 24](https://img.shields.io/badge/node-24-339933?logo=node.js&logoColor=white)
![zero dependencies](https://img.shields.io/badge/dependencies-0-blue)

Pulse probes a site the way a browser would — fresh connection, real timings —
and grades what it finds across three categories:

| Category | Points | What's measured |
|---|---|---|
| **Performance** | 40 | Time to first byte, full response time, TLS handshake, DNS lookup |
| **Security** | 35 | HTTPS, TLS version, certificate validity, HSTS, CSP, `X-Content-Type-Options`, clickjacking protection, `Referrer-Policy` |
| **Best practices** | 25 | Compression (brotli/gzip), HTTP/2 support (ALPN probe), caching headers, redirect-chain length, `Server` header version disclosure |

The UI is a single dark, minimal page: an animated score ring, timing stat
tiles, and per-check pass/warn/fail rows with hints on what to fix.

## Run it

No dependencies — plain Node.js (≥ 20, built for 24):

```bash
node server.js
# → http://localhost:3000
```

## API

```
GET /api/analyze?url=example.com
```

Returns the full report as JSON: score, grade, per-hop timings, redirect
chain, and every check with its points, status, and hint. `POST` with a JSON
body `{"url": "..."}` works too.

```
GET /status
```

Health endpoint, returns `{"ok": true}`.

## How it works

- **Timings** come from socket events (`lookup`, `connect`, `secureConnect`,
  first byte) on a fresh, non-keep-alive connection per request.
- **HTTP/2 detection** is a separate TLS connection with ALPN
  `['h2', 'http/1.1']` — Node's `https` module only speaks 1.1 itself.
- **TLS details** (protocol version, issuer, certificate expiry) are read off
  the peer certificate during the handshake.
- **Redirects** are followed manually (up to 5 hops) so the chain length can
  be scored.
- **SSRF guard**: every hop — including IP-literal hosts, which bypass Node's
  `lookup` hook — is checked against private, loopback, link-local, and
  carrier-grade NAT ranges before any connection is made.

Scores are heuristic, measured in a single pass from wherever the server
runs. Treat them as a direction, not an audit.

## Deploy on Zerops

The repo includes a [`zerops.yaml`](zerops.yaml) — a single `nodejs@24`
service, no build step. See [zerops.io](https://zerops.io) docs for importing
a service from a repository.
