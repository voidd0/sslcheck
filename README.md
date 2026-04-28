# sslcheck

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

## License

MIT — part of the [vøiddo](https://voiddo.com) tools collection.

Built by vøiddo, a small studio shipping AI-flavoured tools, browser extensions and weird browser games.
