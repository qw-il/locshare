/*
 * CPace over X25519 — a balanced PAKE (draft-irtf-cfrg-cpace) for LocShare pairing codes.
 *
 * Two devices that know the same short code each derive a secret generator point from it,
 * do a Diffie-Hellman exchange on that generator, and end up with the same strong key.
 * Someone watching (or relaying) the exchange learns nothing they could brute-force offline:
 * each attempt to guess the code requires talking to a live participant, and the host
 * invalidates the code after a single failed attempt.
 *
 * Hash-to-curve is Elligator 2 for Curve25519 (RFC 9380, §6.7.1) done with BigInt arithmetic;
 * the scalar multiplications use tweetnacl's constant-time X25519.
 */
(function (root) {
  'use strict';
  const nacl = root.nacl || (typeof require === 'function' ? require('tweetnacl') : null);

  // ---- GF(2^255 - 19)
  const P = (1n << 255n) - 19n;
  const A = 486662n;
  const mod = (a) => ((a % P) + P) % P;
  function pow(b, e) {
    let r = 1n;
    b = mod(b);
    while (e > 0n) {
      if (e & 1n) r = (r * b) % P;
      b = (b * b) % P;
      e >>= 1n;
    }
    return r;
  }
  const inv = (a) => pow(a, P - 2n);
  const isSquare = (a) => { const l = pow(a, (P - 1n) / 2n); return l === 0n || l === 1n; };

  function leToBig(bytes) {
    let n = 0n;
    for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
    return n;
  }
  function bigToLe(n) {
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) { out[i] = Number(n & 0xffn); n >>= 8n; }
    return out;
  }

  // Elligator 2 (Z = 2): maps a field element to the u-coordinate of a Curve25519 point.
  function elligator2(r) {
    const t = mod(1n + 2n * r * r);
    const x1 = t === 0n ? mod(-A) : mod(-A * inv(t));
    const gx1 = mod(x1 * x1 * x1 + A * x1 * x1 + x1);
    return isSquare(gx1) ? x1 : mod(-x1 - A);
  }

  // ---- hashing with unambiguous (length-prefixed) encoding
  const enc = new TextEncoder();
  function lv(parts) {
    const bufs = parts.map((p) => (typeof p === 'string' ? enc.encode(p) : p));
    const out = new Uint8Array(bufs.reduce((s, b) => s + 2 + b.length, 0));
    let o = 0;
    for (const b of bufs) { out[o++] = b.length & 0xff; out[o++] = b.length >> 8; out.set(b, o); o += b.length; }
    return out;
  }
  const hash = (...parts) => nacl.hash(lv(parts));

  function generator(code, sid) {
    const h = hash('LocShare/CPace/generator/v1', code, sid).slice(0, 32);
    h[31] &= 0x7f;
    return bigToLe(elligator2(mod(leToBig(h))));
  }

  /** Step 1: pick a secret scalar and compute the public share for this code + session id. */
  function start(code, sid) {
    const y = nacl.randomBytes(32);
    return { y, Y: nacl.scalarMult(y, generator(code, sid)) };
  }

  /** Step 2: combine with the peer's share. Both sides get identical keys only if the codes matched. */
  function finish(state, sid, peerY, isHost) {
    if (!(peerY instanceof Uint8Array) || peerY.length !== 32) throw new Error('Bad pairing message');
    const K = nacl.scalarMult(state.y, peerY);
    if (K.every((b) => b === 0)) throw new Error('Bad pairing message'); // low-order point
    const [Ya, Yb] = isHost ? [state.Y, peerY] : [peerY, state.Y];
    const isk = hash('LocShare/CPace/isk/v1', sid, K, Ya, Yb);
    state.y.fill(0);
    return {
      key: hash('key', isk).slice(0, 32),
      hostTag: hash('host-confirm', isk).slice(0, 16),
      guestTag: hash('guest-confirm', isk).slice(0, 16),
    };
  }

  const api = { start, finish, generator, elligator2, P, A };
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.CPace = api;
})(typeof self !== 'undefined' ? self : this);
