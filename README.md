# sslcheck

[![npm version](https://img.shields.io/npm/v/@v0idd0/sslcheck.svg?color=A0573A)](https://www.npmjs.com/package/@v0idd0/sslcheck)
[![npm downloads](https://img.shields.io/npm/dw/@v0idd0/sslcheck.svg?color=1F1A14)](https://www.npmjs.com/package/@v0idd0/sslcheck)
[![License: MIT](https://img.shields.io/badge/license-MIT-A0573A.svg)](LICENSE)
[![Node ≥14](https://img.shields.io/badge/node-%E2%89%A514-1F1A14)](package.json)

Inspect TLS certificates for any host:port. Reports issuer, SANs, validity window, days-until-expiry, key strength, chain depth. Zero deps. Free forever from vøiddo.

```
$ sslcheck voiddo.com
voiddo.com:443  [ok]
  cn       voiddo.com
  sans     voiddo.com, www.voiddo.com
  issuer   R12
  valid    Mar 31 05:05:45 2026 GMT  →  Jun 29 05:05:44 2026 GMT
  expires  62 days (lifetime 90 days)
  key      RSA 2048 bits
  conn     TLSv1.3  TLS_AES_256_GCM_SHA384 (TLSv1.3)  36ms
  chain    3 cert(s)
```

## Why sslcheck

You set up a Let's Encrypt cert eight months ago. Your auto-renew cron is supposed to handle it. Sometimes it doesn't, and the first sign is a customer pinging you about a browser warning. `openssl s_client -connect host:443 -servername host` does the same job, but the output is a wall of base64 that requires three more pipes to decode. sslcheck is the same probe formatted for human triage and shaped for cron exit codes.

## Install

```bash
npm install -g @v0idd0/sslcheck
```

## Usage

```bash
# Single host (port defaults to 443)
sslcheck voiddo.com

# Multiple hosts
sslcheck github.com npmjs.com cloudflare.com

# Custom port
sslcheck mta.example.com:587

# Override SNI (useful for self-signed / shared infra)
sslcheck self-signed.badssl.com --servername example.com

# JSON for CI / scripts
sslcheck voiddo.com --json | jq '.leaf.days_until_expiry'

# Dump leaf cert as PEM
sslcheck voiddo.com --json --pem | jq -r '.pem' > leaf.pem

# Custom timeout (ms, default 8000)
sslcheck slow-host.example.com --timeout 15000
```

## What it reports

| Field | Meaning |
|---|---|
| `severity` | `ok` / `warn` / `critical` (also drives exit code) |
| `reasons` | Why severity isn't `ok` (e.g., `"expires in 14 days"`, `"self-signed"`) |
| `leaf.common_name` | The CN on the leaf cert |
| `leaf.sans` | All `subjectAltName` DNS entries |
| `leaf.issuer_cn` | Who signed it |
| `leaf.valid_from` / `valid_to` | Cert validity window |
| `leaf.days_until_expiry` | Negative if expired |
| `leaf.key_type` / `key_bits` | RSA 2048, ECDSA P-256, etc. |
| `leaf.fingerprint_sha256` | For pinning / monitoring |
| `protocol` / `cipher` | Negotiated TLS version + cipher suite |
| `chain_length` | Number of certs in the served chain |
| `authorized` | Did node's default trust store accept this chain? |

## Severity rules

- `critical` — expired, expires in ≤ 7 days, RSA key < 2048 bits, or chain not authorized
- `warn` — expires in ≤ 30 days, or self-signed
- `ok` — none of the above

Exit code is `1` on any `critical`, `0` otherwise — wire it directly into monitors/CI.

## Compared to alternatives

| tool | exit code | JSON | per-cert key strength | offline | install |
|---|---|---|---|---|---|
| sslcheck | yes (severity-based) | yes | yes | needs network for handshake | one npm install |
| `openssl s_client` | always 0 unless connection fails | no | manual | needs network | bundled |
| `testssl.sh` | yes | yes (huge) | yes (deep) | needs network | bash + many deps |
| SSL Labs (web) | n/a | yes (API) | yes | no | web only |
| `openssl x509 -in cert.pem` | manual | no | manual | yes (file-only) | bundled |

For a comprehensive cipher-suite + protocol weakness audit, `testssl.sh` is the deeper tool. For "is this cert about to expire?" run by cron every morning, sslcheck is the smaller hammer.

## FAQ

**Why default 8s timeout?** Because some hosts negotiate TLS slowly through carrier-grade NAT / corporate proxies, and 8s is enough for typical pathological cases without making CI feel hung.

**Does it check OCSP?** No. OCSP stapling is increasingly skipped by browsers in favour of CRLite-style models, and our default checks (expiry / chain / key strength) cover the operationally relevant failure modes.

**SANs longer than the terminal width?** They wrap. Use `--json` for programmatic parsing.

**What does `authorized: false` mean?** Node's default trust store rejected the chain. Could be self-signed, could be unknown CA, could be missing intermediate. Pair with `--servername` if you suspect SNI mismatch.

## CI / cron usage

```bash
# Daily expiry watcher (cron)
sslcheck \
  voiddo.com \
  api.voiddo.com \
  scrb.voiddo.com \
  --json | \
  jq -e '[.[]|select(.leaf.days_until_expiry < 14)]|length == 0' \
  || alert-ops "TLS cert nearing expiry"
```

## Programmatic API

```javascript
const { inspect } = require('@v0idd0/sslcheck');

const r = await inspect('voiddo.com', { timeout: 5000 });
if (r.severity === 'critical') {
  console.error(`${r.target} — ${r.reasons.join('; ')}`);
}
```

## More from the studio

This is one tool out of many — see [`from-the-studio.md`](from-the-studio.md) for the full lineup of vøiddo products (other CLI tools, browser extensions, the studio's flagship products and games).

## License

MIT.

---

Built by [vøiddo](https://voiddo.com/) — a small studio shipping AI-flavoured products, free dev tools, Chrome extensions and weird browser games.
