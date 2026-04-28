#!/usr/bin/env node
'use strict';

const { inspect } = require('../src/index');

const HELP = `sslcheck — inspect TLS certificates for any host:port.

Usage:
  sslcheck <host[:port]> [<host[:port]> ...] [options]

Options:
  --json              JSON output (single object for one target, array for many).
  --servername <sni>  Override SNI (default: target host).
  --timeout <ms>      Connect/handshake timeout in ms (default: 8000).
  --pem               Include leaf certificate PEM in JSON output.
  -h, --help          Show this help.

Exit codes:
  0  all certs ok (or --json output)
  1  any cert critical (expired, weak key, chain not authorized)
  2  invalid arguments

Examples:
  sslcheck voiddo.com
  sslcheck github.com:443 npmjs.com cloudflare.com
  sslcheck expired.badssl.com
  sslcheck self-signed.badssl.com --servername example.com
  sslcheck voiddo.com --json | jq '.leaf.days_until_expiry'
`;

function parseArgs(argv) {
  const targets = [];
  const opts = { json: false, includePem: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') { opts.help = true; continue; }
    if (a === '--json') { opts.json = true; continue; }
    if (a === '--pem') { opts.includePem = true; continue; }
    if (a === '--servername') { opts.servername = argv[++i]; continue; }
    if (a === '--timeout') { opts.timeout = parseInt(argv[++i], 10); continue; }
    if (a.startsWith('-')) { console.error('unknown option: ' + a); process.exit(2); }
    targets.push(a);
  }
  return { targets, opts };
}

const isTTY = process.stdout.isTTY;
const C = {
  reset: isTTY ? '\x1b[0m' : '',
  dim:   isTTY ? '\x1b[2m' : '',
  bold:  isTTY ? '\x1b[1m' : '',
  red:   isTTY ? '\x1b[31m' : '',
  yel:   isTTY ? '\x1b[33m' : '',
  grn:   isTTY ? '\x1b[32m' : '',
  cya:   isTTY ? '\x1b[36m' : '',
};

function sevColor(sev) {
  if (sev === 'critical') return C.red;
  if (sev === 'warn') return C.yel;
  if (sev === 'ok') return C.grn;
  return '';
}

function truncate(s, n) {
  if (!s) return '';
  if (s.length <= n) return s;
  return s.slice(0, n - 1) + '…';
}

function printHuman(r) {
  const sevC = sevColor(r.severity);
  console.log(C.bold + r.target + C.reset + '  ' + sevC + '[' + r.severity + ']' + C.reset +
    (r.reasons && r.reasons.length ? '  ' + C.dim + r.reasons.join('; ') + C.reset : ''));
  if (r.error) {
    console.log('  ' + C.red + 'error:' + C.reset + ' ' + r.error);
    return;
  }
  if (r.leaf) {
    console.log('  cn       ' + (r.leaf.common_name || '(none)'));
    if (r.leaf.sans && r.leaf.sans.length) {
      const shown = r.leaf.sans.slice(0, 6).join(', ');
      const more = r.leaf.sans.length > 6 ? ' (+' + (r.leaf.sans.length - 6) + ' more)' : '';
      console.log('  sans     ' + shown + more);
    }
    console.log('  issuer   ' + (r.leaf.issuer_cn || truncate(r.leaf.issuer || '', 80)));
    console.log('  valid    ' + r.leaf.valid_from + '  →  ' + r.leaf.valid_to);
    const daysC = r.leaf.days_until_expiry < 0 ? C.red :
                  r.leaf.days_until_expiry <= 30 ? C.yel : C.grn;
    console.log('  expires  ' + daysC + r.leaf.days_until_expiry + ' days' + C.reset +
      C.dim + ' (lifetime ' + r.leaf.lifetime_days + ' days)' + C.reset);
    console.log('  key      ' + (r.leaf.key_type || '?') + ' ' + (r.leaf.key_bits ? r.leaf.key_bits + ' bits' : ''));
  }
  if (r.protocol || r.cipher) {
    const c = r.cipher ? r.cipher.name + ' (' + r.cipher.version + ')' : '?';
    console.log('  conn     ' + (r.protocol || '?') + '  ' + c + C.dim + '  ' + r.elapsed_ms + 'ms' + C.reset);
  }
  console.log('  chain    ' + (r.chain_length || 1) + ' cert(s)');
}

async function main() {
  const argv = process.argv.slice(2);
  const { targets, opts } = parseArgs(argv);
  if (opts.help || targets.length === 0) {
    process.stdout.write(HELP);
    process.exit(targets.length === 0 && !opts.help ? 2 : 0);
  }
  const results = [];
  for (const t of targets) {
    try {
      const r = await inspect(t, opts);
      results.push(r);
    } catch (e) {
      results.push({ target: t, severity: 'critical', error: e.message, reasons: [e.message] });
    }
  }
  if (opts.json) {
    const out = results.length === 1 ? results[0] : results;
    process.stdout.write(JSON.stringify(out, null, 2) + '\n');
  } else {
    for (let i = 0; i < results.length; i++) {
      if (i > 0) console.log('');
      printHuman(results[i]);
    }
  }
  const anyCritical = results.some(r => r.severity === 'critical');
  process.exit(anyCritical ? 1 : 0);
}

main().catch(e => { console.error(e.stack || e.message); process.exit(2); });
