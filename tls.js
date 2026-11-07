'use strict';
/*
 * Self-signed TLS certificate for `npm run https`, generated with Node's crypto only (no openssl).
 *
 * Browsers only allow features like "choose where to save" on secure (HTTPS) pages. This builds a
 * small ECDSA P-256 X.509 certificate covering localhost and every LAN address of this machine.
 * It's cached in .locshare/ so browsers only need to accept it once; it is regenerated when the
 * machine's addresses change or it nears expiry. The certificate holds no user data.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ---- minimal DER encoder
function len(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  while (n > 0) { bytes.unshift(n & 0xff); n >>= 8; }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
const der = (tag, ...parts) => { const body = Buffer.concat(parts.map((p) => Buffer.from(p))); return Buffer.concat([Buffer.from([tag]), len(body.length), body]); };
const seq = (...p) => der(0x30, ...p);
const set = (...p) => der(0x31, ...p);
const octets = (...p) => der(0x04, ...p);
const ctx = (n, ...p) => der(0xa0 + n, ...p);
function int(buf) {
  buf = Buffer.from(buf);
  if (buf[0] & 0x80) buf = Buffer.concat([Buffer.from([0]), buf]);
  return der(0x02, buf);
}
function oid(str) {
  const [a, b, ...rest] = str.split('.').map(Number);
  const out = [40 * a + b];
  for (let v of rest) {
    const chunk = [v & 0x7f];
    while ((v >>= 7) > 0) chunk.unshift(0x80 | (v & 0x7f));
    out.push(...chunk);
  }
  return der(0x06, Buffer.from(out));
}
function time(d) {
  const iso = d.toISOString().replace(/[-:T]/g, '').slice(0, 14) + 'Z'; // YYYYMMDDHHMMSSZ
  return d.getUTCFullYear() < 2050 ? der(0x17, iso.slice(2)) : der(0x18, iso);
}

const ECDSA_SHA256 = '1.2.840.10045.4.3.2';

function buildCert(hosts, ips, days) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const name = seq(set(seq(oid('2.5.4.3'), der(0x0c, 'LocShare (this computer)'))));
  const now = Date.now();
  const serial = crypto.randomBytes(16);
  serial[0] &= 0x7f;
  const san = seq(
    ...hosts.map((h) => der(0x82, h)),                                  // dNSName
    ...ips.map((ip) => der(0x87, Buffer.from(ip.split('.').map(Number)))), // iPAddress (IPv4)
  );
  const tbs = seq(
    ctx(0, int([2])),                                        // X.509 v3
    int(serial),
    seq(oid(ECDSA_SHA256)),
    name,
    seq(time(new Date(now - 864e5)), time(new Date(now + days * 864e5))),
    name,
    publicKey.export({ type: 'spki', format: 'der' }),
    ctx(3, seq(
      seq(oid('2.5.29.19'), der(0x01, [0xff]), octets(seq())),                  // basicConstraints: not a CA (critical)
      seq(oid('2.5.29.15'), der(0x01, [0xff]), octets(der(0x03, [0x07, 0x80]))), // keyUsage: digitalSignature (critical)
      seq(oid('2.5.29.37'), octets(seq(oid('1.3.6.1.5.5.7.3.1')))),             // extKeyUsage: serverAuth
      seq(oid('2.5.29.17'), octets(san)),                                       // subjectAltName
    )),
  );
  const sig = crypto.sign('sha256', tbs, privateKey); // DER-encoded ECDSA signature
  const cert = seq(tbs, seq(oid(ECDSA_SHA256)), der(0x03, Buffer.concat([Buffer.from([0]), sig])));
  const pem = `-----BEGIN CERTIFICATE-----\n${cert.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;
  return { cert: pem, key: privateKey.export({ type: 'pkcs8', format: 'pem' }) };
}

/** Load the cached certificate, or create one covering localhost + the given LAN IPv4 addresses. */
function selfSigned(ips, dir) {
  const hosts = ['localhost'];
  const all = ['127.0.0.1', ...ips];
  const file = path.join(dir, 'tls.json');
  try {
    const cached = JSON.parse(fs.readFileSync(file, 'utf8'));
    const x = new crypto.X509Certificate(cached.cert);
    const fresh = new Date(x.validTo).getTime() - Date.now() > 30 * 864e5;
    const covers = all.every((ip) => (x.subjectAltName || '').includes(`IP Address:${ip}`));
    if (fresh && covers) return { ...cached, fingerprint: x.fingerprint256, created: false };
  } catch { /* none yet, or unreadable — make a new one */ }
  const made = buildCert(hosts, all, 397); // stay within browsers' 398-day limit
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, JSON.stringify(made), { mode: 0o600 });
  return { ...made, fingerprint: new crypto.X509Certificate(made.cert).fingerprint256, created: true };
}

module.exports = { selfSigned, buildCert };
