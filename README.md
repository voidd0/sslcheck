# sslcheck

Inspect the TLS certificate of a host and port: issuer, SANs, validity dates, days until expiry, key size and chain length. Use it by hand to triage a certificate warning, or in cron and CI, where the exit code tells you if something is critical.

[![npm](https://img.shields.io/npm/v/@v0idd0/sslcheck?color=00f6d0&labelColor=050914)](https://www.npmjs.com/package/@v0idd0/sslcheck)
[![test](https://github.com/voidd0/sslcheck/actions/workflows/test.yml/badge.svg)](https://github.com/voidd0/sslcheck/actions/workflows/test.yml)
[![license](https://img.shields.io/badge/license-MIT-00f6d0?labelColor=050914)](LICENSE)

## Install

```bash
npm install -g @v0idd0/sslcheck
```

Or run it once without installing: `npx @v0idd0/sslcheck --help`. Needs Node.js 18 or newer. No dependencies.

## Example

Check two hosts in one call. Output from a real run on 2026-11-26:

```console
$ sslcheck example.com github.com
example.com:443  [ok]
  cn       example.com
  sans     example.com, *.example.com
  issuer   Cloudflare TLS Issuing ECC CA 3
  valid    Nov 24 23:48:34 2026 GMT  →  Feb 22 23:53:08 2027 GMT
  expires  88 days (lifetime 90 days)
  key      prime256v1 256 bits
  conn     TLSv1.3  TLS_AES_256_GCM_SHA384 (TLSv1.3)  45ms
  chain    4 cert(s)

github.com:443  [ok]
  cn       github.com
  sans     github.com, www.github.com
  issuer   Sectigo Public Server Authentication CA DV E36
  valid    Oct 30 00:00:00 2026 GMT  →  Jan 27 23:59:59 2027 GMT
  expires  62 days (lifetime 90 days)
  key      prime256v1 256 bits
  conn     TLSv1.3  TLS_AES_128_GCM_SHA256 (TLSv1.3)  27ms
  chain    4 cert(s)
```

A host that does not resolve gives one clear line and exit code 1, not a stack trace:

```console
$ sslcheck nonexistent.invalid
nonexistent.invalid:443  [critical]  ENOTFOUND: getaddrinfo ENOTFOUND nonexistent.invalid
  error: getaddrinfo ENOTFOUND nonexistent.invalid
```

## Usage

```text
sslcheck: inspect the TLS certificate of a host and port.

Usage:
  sslcheck <host[:port]> [<host[:port]> ...] [options]

Options:
  --json              JSON output (single object for one target, array for many).
  --servername <sni>  Override SNI (default: target host).
  --timeout <ms>      Connect/handshake timeout in ms (default: 8000).
  --pem               Include leaf certificate PEM in JSON output.
  -h, --help          Show this help.

Exit codes:
  0  no critical result (ok or warn), also with --json
  1  any target critical (expired or expiring within 7 days, weak RSA key,
     chain not authorized, no connection)
  2  invalid arguments

Examples:
  sslcheck example.com
  sslcheck github.com:443 example.com
  sslcheck expired.badssl.com
  sslcheck example.com --json | jq '.leaf.days_until_expiry'

Docs and issues: https://github.com/voidd0/sslcheck
```

## Limits

- The check connects with certificate verification turned off so it can still read broken certificates. Whether the chain is trusted is reported separately (`authorized` in the JSON output), using the CA list that ships with your Node.js.
- A result is `critical` when the certificate has expired or expires within 7 days, the chain is not authorized, an RSA key is under 2048 bits, or the connection fails. It is `warn` at 30 days or less, or when the certificate is self-signed.
- The tests that touch the network use example.com. If there is no connection they skip themselves. Set `SSLCHECK_SKIP_NETWORK=1` to skip them on purpose.

## License

MIT, see [LICENSE](LICENSE).

---

Made by [vøiddo](https://voiddo.com/?src=gh). More command line tools: [voiddo.com/packages](https://voiddo.com/packages/?src=gh).
We also run data scrapers for job boards, shops and ad libraries: [voiddo.com/scrapers](https://voiddo.com/scrapers/?src=gh).
