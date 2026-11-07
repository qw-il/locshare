/*
 * LocShare background encryption: seals and opens file blocks off the main thread, one worker per
 * CPU core, so big transfers use several cores and the page stays smooth.
 *
 *  - "aes-256-gcm":      hardware-accelerated WebCrypto (HTTPS pages)
 *  - "xsalsa20poly1305": tweetnacl secretbox (plain-HTTP pages, where WebCrypto is unavailable)
 *
 * Wire format for both: a 24-byte header, then ciphertext + 16-byte tag. Receivers never trust the
 * header — they recompute the nonce from the block index, so blocks can't be swapped or reordered.
 */
'use strict';
importScripts('/vendor/nacl.js');

const HEADER = 24;
const aesKeys = new Map();

function naclNonce(prefix, index) {
  const n = new Uint8Array(24);
  n.set(prefix.subarray(0, 16), 0);
  new DataView(n.buffer).setBigUint64(16, BigInt(index));
  return n;
}
function aesIv(prefix, index) {
  const iv = new Uint8Array(12);
  iv.set(prefix.subarray(0, 4), 0);
  new DataView(iv.buffer).setBigUint64(4, BigInt(index));
  return iv;
}
async function aesKey(raw) {
  const id = Array.from(raw, (b) => b.toString(16).padStart(2, '0')).join('');
  if (!aesKeys.has(id)) {
    if (aesKeys.size > 32) aesKeys.clear();
    aesKeys.set(id, crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']));
  }
  return aesKeys.get(id);
}

async function run(m) {
  const data = new Uint8Array(m.data);
  if (m.cipher === 'aes-256-gcm') {
    const iv = aesIv(m.prefix, m.index);
    const key = await aesKey(m.key);
    if (m.op === 'seal') {
      const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data));
      data.fill(0);
      const out = new Uint8Array(HEADER + ct.length);
      out.set(iv, 0);
      out.set(ct, HEADER);
      return out;
    }
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data.subarray(HEADER)));
  }
  const nonce = naclNonce(m.prefix, m.index);
  if (m.op === 'seal') {
    const box = nacl.secretbox(data, nonce, m.key);
    data.fill(0);
    const out = new Uint8Array(HEADER + box.length);
    out.set(nonce, 0);
    out.set(box, HEADER);
    return out;
  }
  const plain = nacl.secretbox.open(data.subarray(HEADER), nonce, m.key);
  if (!plain) throw new Error('tamper');
  return plain;
}

self.onmessage = async ({ data: m }) => {
  try {
    const out = await run(m);
    self.postMessage({ id: m.id, out: out.buffer, off: out.byteOffset, len: out.length }, [out.buffer]);
  } catch (err) {
    self.postMessage({ id: m.id, error: m.op === 'open' ? 'tamper' : String(err && err.message || err) });
  }
};
