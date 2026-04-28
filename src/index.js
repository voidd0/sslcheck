// sslcheck — inspect TLS certificates for any host:port. Reports issuer,
// subject, SANs, validity window, days-until-expiry, key/sig strength,
// and a simple chain depth count. Zero runtime dependencies — built on
// node's tls module.

'use strict';

const tls = require('tls');

const DEFAULT_PORT = 443;
const DEFAULT_TIMEOUT_MS = 8000;

function parseTarget(target) {
  if (!target || typeof target !== 'string') {
    throw new Error('target must be a non-empty string like "host" or "host:port"');
  }
  const t = target.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').trim();
  if (!t) throw new Error('empty target after cleanup');
  if (t.includes(':')) {
    const [host, portStr] = t.split(':');
    const port = parseInt(portStr, 10);
    if (!port || port < 1 || port > 65535) throw new Error('invalid port: ' + portStr);
    return { host, port };
  }
  return { host: t, port: DEFAULT_PORT };
}

function daysBetween(a, b) {
  return Math.round((a.getTime() - b.getTime()) / 86400000);
}

function pemFromDer(derB64) {
  const lines = [];
  for (let i = 0; i < derB64.length; i += 64) lines.push(derB64.slice(i, i + 64));
  return '-----BEGIN CERTIFICATE-----\n' + lines.join('\n') + '\n-----END CERTIFICATE-----\n';
}

function flattenName(n) {
  if (!n || typeof n !== 'object') return null;
  const order = ['CN', 'O', 'OU', 'C', 'L', 'ST', 'emailAddress'];
  const parts = [];
  for (const k of order) if (n[k]) parts.push(k + '=' + n[k]);
  for (const k of Object.keys(n)) {
    if (!order.includes(k) && n[k]) parts.push(k + '=' + n[k]);
  }
  return parts.length ? parts.join(', ') : null;
}

function parseSans(subjectaltname) {
  if (!subjectaltname) return [];
  return subjectaltname.split(/, ?/).map(s => s.replace(/^DNS:/, '').trim()).filter(Boolean);
}

function summarizeCert(cert, now) {
  if (!cert || !cert.subject) return null;
  const validFrom = new Date(cert.valid_from);
  const validTo = new Date(cert.valid_to);
  const daysUntilExpiry = daysBetween(validTo, now);
  const lifetimeDays = daysBetween(validTo, validFrom);
  return {
    subject: flattenName(cert.subject),
    common_name: cert.subject ? cert.subject.CN || null : null,
    issuer: flattenName(cert.issuer),
    issuer_cn: cert.issuer ? cert.issuer.CN || null : null,
    serial: cert.serialNumber || null,
    sans: parseSans(cert.subjectaltname),
    valid_from: cert.valid_from || null,
    valid_to: cert.valid_to || null,
    days_until_expiry: daysUntilExpiry,
    lifetime_days: lifetimeDays,
    key_type: cert.asn1Curve || (cert.modulus ? 'RSA' : (cert.pubkey ? 'unknown' : null)),
    key_bits: cert.bits || null,
    fingerprint_sha256: cert.fingerprint256 || null,
    sig_algorithm: cert.asn1SigAlg || null,
    self_signed: cert.issuer && cert.subject &&
      flattenName(cert.issuer) === flattenName(cert.subject) || false,
  };
}

function classify(summary, authorized, authError) {
  const reasons = [];
  let severity = 'ok';
  if (!summary) {
    return { severity: 'critical', reasons: ['no peer certificate returned'] };
  }
  if (summary.days_until_expiry < 0) {
    severity = 'critical';
    reasons.push('certificate expired ' + Math.abs(summary.days_until_expiry) + ' days ago');
  } else if (summary.days_until_expiry <= 7) {
    severity = 'critical';
    reasons.push('expires in ' + summary.days_until_expiry + ' days');
  } else if (summary.days_until_expiry <= 30) {
    severity = 'warn';
    reasons.push('expires in ' + summary.days_until_expiry + ' days');
  }
  if (summary.self_signed) {
    if (severity === 'ok') severity = 'warn';
    reasons.push('self-signed');
  }
  if (!authorized && authError) {
    severity = 'critical';
    reasons.push('chain not authorized: ' + authError);
  }
  if (summary.key_bits && summary.key_bits < 2048 && /RSA/i.test(summary.key_type || '')) {
    severity = 'critical';
    reasons.push('weak RSA key: ' + summary.key_bits + ' bits');
  }
  return { severity, reasons };
}

function inspect(target, opts) {
  opts = opts || {};
  const { host, port } = parseTarget(target);
  const timeoutMs = opts.timeout || DEFAULT_TIMEOUT_MS;
  const servername = opts.servername || host;

  return new Promise((resolve) => {
    const start = Date.now();
    const finish = (err, payload) => {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch (_) {}
      const elapsed_ms = Date.now() - start;
      if (err) {
        resolve({
          target: host + ':' + port,
          host, port, servername,
          error: err.message || String(err),
          severity: 'critical',
          reasons: [err.code ? err.code + ': ' + (err.message || '') : (err.message || 'unknown error')],
          elapsed_ms,
        });
        return;
      }
      resolve(Object.assign({
        target: host + ':' + port,
        host, port, servername,
        elapsed_ms,
      }, payload));
    };
    let settled = false;

    const socket = tls.connect({
      host,
      port,
      servername,
      rejectUnauthorized: false,
      timeout: timeoutMs,
    }, () => {
      const cert = socket.getPeerCertificate(true);
      const proto = socket.getProtocol();
      const cipher = socket.getCipher();
      const authorized = socket.authorized;
      const authError = socket.authorizationError ? String(socket.authorizationError) : null;
      const now = new Date();
      const summary = summarizeCert(cert, now);
      const chain = [];
      let walker = cert;
      let depth = 0;
      const seenFps = new Set();
      while (walker && walker.subject && !seenFps.has(walker.fingerprint256)) {
        seenFps.add(walker.fingerprint256);
        chain.push(summarizeCert(walker, now));
        if (!walker.issuerCertificate || walker.issuerCertificate === walker) break;
        walker = walker.issuerCertificate;
        if (++depth > 16) break;
      }
      const classification = classify(summary, authorized, authError);
      const pem = (cert && cert.raw) ? pemFromDer(cert.raw.toString('base64')) : null;
      finish(null, {
        leaf: summary,
        chain,
        chain_length: chain.length,
        protocol: proto,
        cipher: cipher ? { name: cipher.name, version: cipher.version } : null,
        authorized,
        auth_error: authError,
        severity: classification.severity,
        reasons: classification.reasons,
        pem: opts.includePem ? pem : undefined,
      });
    });
    socket.setTimeout(timeoutMs, () => finish(new Error('connection timed out after ' + timeoutMs + 'ms')));
    socket.on('error', (e) => finish(e));
  });
}

module.exports = { inspect, parseTarget, summarizeCert, classify, DEFAULT_PORT, DEFAULT_TIMEOUT_MS };
