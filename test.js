/* sslcheck — smoke tests. Run via: node test.js */
'use strict';

const { parseTarget, summarizeCert, classify, inspect, DEFAULT_PORT } = require('./src/index');

let passed = 0, failed = 0;
function eq(label, a, b) {
  if (JSON.stringify(a) === JSON.stringify(b)) { console.log('  ok  ' + label); passed++; }
  else { console.log('  FAIL ' + label); console.log('     actual:   ' + JSON.stringify(a)); console.log('     expected: ' + JSON.stringify(b)); failed++; }
}
function truthy(label, v) { if (v) { console.log('  ok  ' + label); passed++; } else { console.log('  FAIL ' + label); failed++; } }

console.log('parseTarget:');
eq('host only',          parseTarget('voiddo.com'),                { host: 'voiddo.com', port: 443 });
eq('host:port',          parseTarget('example.com:8443'),          { host: 'example.com', port: 8443 });
eq('strips https://',    parseTarget('https://voiddo.com'),        { host: 'voiddo.com', port: 443 });
eq('strips path',        parseTarget('https://voiddo.com/foo/bar'),{ host: 'voiddo.com', port: 443 });
eq('default port const', DEFAULT_PORT, 443);

console.log('\nsummarizeCert:');
const fakeCert = {
  subject: { CN: 'voiddo.com', O: 'voiddo' },
  issuer:  { CN: 'Test CA' },
  serialNumber: 'AABBCC',
  subjectaltname: 'DNS:voiddo.com, DNS:www.voiddo.com',
  valid_from: 'Apr  1 00:00:00 2026 GMT',
  valid_to:   'Jul  1 00:00:00 2026 GMT',
  fingerprint256: 'AA:BB:CC',
  bits: 2048,
};
const sum = summarizeCert(fakeCert, new Date('2026-04-28T00:00:00Z'));
eq('common_name',  sum.common_name,    'voiddo.com');
eq('issuer_cn',    sum.issuer_cn,      'Test CA');
eq('sans parsed',  sum.sans,           ['voiddo.com', 'www.voiddo.com']);
truthy('days_until_expiry positive',  sum.days_until_expiry > 0);
truthy('lifetime ~91 days',            Math.abs(sum.lifetime_days - 91) <= 1);
eq('key_bits',     sum.key_bits,        2048);

console.log('\nclassify:');
const okSum = { days_until_expiry: 60, self_signed: false, key_bits: 4096, key_type: 'RSA' };
eq('ok cert',          classify(okSum, true, null).severity,  'ok');
const warnSum = { days_until_expiry: 14, self_signed: false, key_bits: 4096, key_type: 'RSA' };
eq('14d → warn',       classify(warnSum, true, null).severity, 'warn');
const expSum  = { days_until_expiry: -5, self_signed: false, key_bits: 4096, key_type: 'RSA' };
eq('expired → critical', classify(expSum, true, null).severity, 'critical');
const ssSum   = { days_until_expiry: 60, self_signed: true,  key_bits: 4096, key_type: 'RSA' };
eq('self-signed → warn', classify(ssSum, true, null).severity, 'warn');
const weakSum = { days_until_expiry: 60, self_signed: false, key_bits: 1024, key_type: 'RSA' };
eq('weak rsa → critical', classify(weakSum, true, null).severity, 'critical');
const unauth  = { days_until_expiry: 60, self_signed: false, key_bits: 4096, key_type: 'RSA' };
eq('unauth → critical',   classify(unauth, false, 'CERT_HAS_EXPIRED').severity, 'critical');

console.log('\nlive inspect (network):');
const onlineTest = (async () => {
  const skip = process.env.SSLCHECK_SKIP_NETWORK === '1';
  if (skip) { console.log('  -- skipped (SSLCHECK_SKIP_NETWORK=1)'); return; }
  try {
    const r = await inspect('voiddo.com', { timeout: 6000 });
    truthy('voiddo.com responded',         !!r.target);
    truthy('voiddo.com leaf has CN',       r.leaf && !!r.leaf.common_name);
    truthy('voiddo.com expiry >= 0 days',  r.leaf && r.leaf.days_until_expiry >= 0);
    truthy('voiddo.com chain has ≥1 cert', r.chain_length >= 1);
    truthy('voiddo.com authorized',        r.authorized === true);
  } catch (e) {
    console.log('  SKIP voiddo.com network test: ' + e.message);
  }
})();

onlineTest.then(() => {
  console.log('\n' + passed + ' passed, ' + failed + ' failed');
  process.exit(failed === 0 ? 0 : 1);
});
