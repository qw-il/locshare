#!/usr/bin/env node
/*
 * LocShare — private file sharing over your local network.
 *
 * Privacy model
 * -------------
 *  - Files are encrypted in the sender's browser (XSalsa20-Poly1305) before upload.
 *    The key lives only in the link's #fragment, which browsers never send to servers.
 *  - File names, types, sizes and notes are encrypted too (inside the manifest).
 *  - Content is padded to fixed-size chunks, so the server only learns a rounded size.
 *  - Everything is kept in RAM only. Nothing is ever written to disk, and nothing is logged.
 *  - There is no size limit: shares too big for the host's memory budget are streamed live
 *    from the sender's browser, block by block, and never stored at all.
 *  - Shares are unlisted (128-bit random IDs), expire automatically and can be revoked
 *    or set to self-destruct after the first download.
 */
'use strict';

const http = require('http');
const https = require('https');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

// ---------------------------------------------------------------- configuration
const PORT = parseInt(process.env.PORT || '8080', 10);
const HOST = process.env.HOST || '0.0.0.0';
const MAX_STORE_BYTES = parseInt(process.env.MAX_STORE_MB || '2048', 10) * 1024 * 1024;
const TLS_CERT = process.env.TLS_CERT;
const TLS_KEY = process.env.TLS_KEY;
// `npm run https` / HTTPS=1: serve over HTTPS with an auto-generated self-signed certificate.
const AUTO_TLS = !TLS_CERT && (process.argv.includes('--https') || /^(1|true|yes)$/i.test(process.env.HTTPS || ''));
const USE_TLS = !!(TLS_CERT && TLS_KEY) || AUTO_TLS;

const CHUNK_SIZE = 1024 * 1024;                 // plaintext bytes per chunk (must match client)
const CHUNK_OVERHEAD = 24 + 16;                 // nonce + Poly1305 tag
const MAX_CHUNK_BODY = CHUNK_SIZE + CHUNK_OVERHEAD;
const MAX_MANIFEST_BODY = 32 * 1024 * 1024;     // room for folders with many thousands of files
const TTL_CHOICES = [5, 15, 60, 360, 1440];     // minutes
const UPLOAD_IDLE_MS = 10 * 60 * 1000;          // unsealed shares die after 10 idle minutes
const LIVE_GRACE_MS = 30 * 1000;                // live shares die if the sender is gone this long
const LIVE_WAIT_MS = 2 * 60 * 1000;             // max wait for the sender to answer a block request

const PUBLIC_DIR = path.join(__dirname, 'public');
const VENDOR = {
  'nacl.js': path.join(__dirname, 'node_modules/tweetnacl/nacl-fast.min.js'),
  'qrcode.js': path.join(__dirname, 'node_modules/qrcode-generator/qrcode.js'),
};

// ---------------------------------------------------------------- in-memory store
/** @type {Map<string, Share>} */
const shares = new Map();
let storedBytes = 0;

function newId(bytes) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function createShare(ttlMin, burn, live) {
  const id = newId(16);
  const share = {
    id,
    ownerToken: newId(24),
    chunks: [],
    manifest: null,
    bytes: 0,
    sealed: false,
    burn: !!burn,
    ttlMs: ttlMin * 60 * 1000,
    expiresAt: Date.now() + UPLOAD_IDLE_MS,
    opens: 0,
    downloads: 0,
    // live (streamed) shares
    live: !!live,
    chunkCount: 0,
    sender: null,          // open response stream to the sender's tab
    pending: new Map(),    // reqId -> { index, res, timer }
    orphanTimer: null,
  };
  if (share.live) share.orphanTimer = setTimeout(() => destroyShare(share), UPLOAD_IDLE_MS);
  shares.set(id, share);
  return share;
}

function destroyShare(share) {
  if (!shares.has(share.id)) return;
  // Drop references and overwrite buffers so ciphertext doesn't linger in memory.
  for (const c of share.chunks) if (c) c.fill(0);
  if (share.manifest) share.manifest.fill(0);
  storedBytes -= share.bytes;
  clearTimeout(share.orphanTimer);
  for (const p of share.pending.values()) { clearTimeout(p.timer); if (!p.res.headersSent) fail(p.res, 410, 'Share is gone'); else p.res.destroy(); }
  share.pending.clear();
  if (share.sender) { share.sender.end('gone\n'); share.sender = null; }
  share.chunks = [];
  share.manifest = null;
  shares.delete(share.id);
}

setInterval(() => {
  const now = Date.now();
  for (const s of shares.values()) if (s.expiresAt <= now) destroyShare(s);
}, 5000).unref();

// ---------------------------------------------------------------- live sessions (paired devices)
// A room is a tiny encrypted message relay between devices that scanned the same QR code.
// Every message is sealed client-side with the room key (which only lives in the link fragment),
// so the server only ever forwards opaque bytes between connected peers.
const ROOM_MAX_PEERS = 8;
const ROOM_MAX_MSG = 256 * 1024;
const ROOM_EMPTY_MS = 2 * 60 * 1000; // an empty room survives briefly so reloads can rejoin

/** @type {Map<string, {id: string, peers: Map<string, {res: any, token: string}>, timer: any}>} */
const rooms = new Map();

function createRoom() {
  const room = { id: newId(16), peers: new Map(), timer: null };
  room.timer = setTimeout(() => closeRoom(room), ROOM_EMPTY_MS);
  rooms.set(room.id, room);
  return room;
}

function closeRoom(room) {
  clearTimeout(room.timer);
  for (const p of room.peers.values()) p.res.end('closed\n');
  room.peers.clear();
  rooms.delete(room.id);
}

function roomBroadcast(room, line, except, only) {
  for (const [id, p] of room.peers) {
    if (id === except || (only && id !== only)) continue;
    p.res.write(line);
  }
}

// ---------------------------------------------------------------- pairing codes
// A short-lived two-party mailbox for the CPace handshake behind codes like "7-291-735".
// The leading number is just a public slot; the six secret digits never reach the server —
// only public PAKE values and a box sealed with the resulting key pass through here.
const PAIR_TTL_MS = 5 * 60 * 1000;
const PAIR_WAIT_MS = 25 * 1000;
const PAIR_MAX_MSG = 8 * 1024;

/** @type {Map<string, any>} */
const pairs = new Map();

// Freed slots rest for a while, so a stale code typed late can't land on (and burn) a fresh one.
const SLOT_COOLDOWN_MS = 10 * 60 * 1000;
const coolingSlots = new Map(); // slot -> time it becomes reusable

function createPair() {
  const now = Date.now();
  for (const [sl, t] of coolingSlots) if (t <= now) coolingSlots.delete(sl);
  const free = (n) => !pairs.has(String(n)) && !coolingSlots.has(String(n));
  let slot = null;
  // Short random slots first (1–99), widening only if the network is unusually busy.
  for (const max of [99, 999, 9999]) {
    for (let tries = 0; tries < 40 && !slot; tries++) {
      const n = 1 + crypto.randomInt(max);
      if (free(n)) slot = String(n);
    }
    if (slot) break;
  }
  if (!slot) return null;
  const pair = {
    slot,
    tokens: { host: newId(18), guest: null },
    queue: { host: [], guest: [] },
    waiter: { host: null, guest: null },
    timer: null,
  };
  pair.timer = setTimeout(() => closePair(pair), PAIR_TTL_MS);
  pairs.set(slot, pair);
  return pair;
}

function closePair(pair) {
  clearTimeout(pair.timer);
  for (const role of ['host', 'guest']) {
    const w = pair.waiter[role];
    if (w) { clearTimeout(w.timer); if (!w.res.headersSent) fail(w.res, 410, 'Pairing code expired'); }
  }
  if (pairs.get(pair.slot) === pair) {
    pairs.delete(pair.slot);
    coolingSlots.set(pair.slot, Date.now() + SLOT_COOLDOWN_MS);
  }
}

function pairRole(req, pair) {
  const t = req.headers['x-pair-token'];
  if (typeof t !== 'string') return null;
  for (const role of ['host', 'guest']) {
    const want = pair.tokens[role];
    if (want && t.length === want.length && crypto.timingSafeEqual(Buffer.from(t), Buffer.from(want))) return role;
  }
  return null;
}

// ---------------------------------------------------------------- http helpers
const SECURITY_HEADERS = {
  'Content-Security-Policy': [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data: blob:",
    "connect-src 'self'",
    "manifest-src 'self'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join('; '),
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
  'Cache-Control': 'no-store',
};

function send(res, status, body, type = 'application/json') {
  if (USE_TLS) res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  const data = typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body);
  res.writeHead(status, { ...SECURITY_HEADERS, 'Content-Type': type, 'Content-Length': Buffer.byteLength(data) });
  res.end(data);
}

const fail = (res, status, error) => send(res, status, { error });

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const parts = [];
    let size = 0;
    req.on('data', (d) => {
      size += d.length;
      if (size > limit) {
        reject(Object.assign(new Error('Payload too large'), { status: 413 }));
        req.destroy();
        return;
      }
      parts.push(d);
    });
    req.on('end', () => resolve(Buffer.concat(parts, size)));
    req.on('error', reject);
  });
}

function isOwner(req, share) {
  const token = req.headers['x-owner-token'];
  if (typeof token !== 'string' || token.length !== share.ownerToken.length) return false;
  return crypto.timingSafeEqual(Buffer.from(token), Buffer.from(share.ownerToken));
}

function publicInfo(share) {
  return {
    sealed: share.sealed,
    chunks: share.live ? share.chunkCount : share.chunks.length,
    live: share.live,
    burn: share.burn,
    expiresAt: share.expiresAt,
  };
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/manifest+json',
  '.png': 'image/png',
};

function serveFile(res, file) {
  fs.readFile(file, (err, data) => {
    if (err) return fail(res, 404, 'Not found');
    send(res, 200, data, MIME[path.extname(file)] || 'application/octet-stream');
  });
}

function lanAddresses() {
  const out = [];
  for (const [name, list] of Object.entries(os.networkInterfaces())) {
    for (const a of list || []) {
      if (a.family === 'IPv4' && !a.internal) out.push({ name, address: a.address });
    }
  }
  return out;
}

// ---------------------------------------------------------------- router
async function handle(req, res) {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;
  const m = req.method;

  try {
    // ---- API -------------------------------------------------------------
    if (p === '/api/info' && m === 'GET') {
      const proto = USE_TLS ? 'https' : 'http';
      return send(res, 200, {
        chunkSize: CHUNK_SIZE,
        ttlChoices: TTL_CHOICES,
        freeBytes: Math.max(0, MAX_STORE_BYTES - storedBytes),
        origins: lanAddresses().map((a) => ({ name: a.name, origin: `${proto}://${a.address}:${PORT}` })),
      });
    }

    if (p === '/api/s' && m === 'POST') {
      const body = JSON.parse((await readBody(req, 1024)).toString() || '{}');
      const ttl = TTL_CHOICES.includes(body.ttl) ? body.ttl : 60;
      const need = Number(body.bytes) || 0;
      // Too big for RAM? The client streams it live instead, so this never limits file size.
      if (!body.live && need > MAX_STORE_BYTES - storedBytes) return fail(res, 507, 'Not enough free memory on the host — use live streaming');
      const s = createShare(ttl, body.burn, body.live);
      return send(res, 201, { id: s.id, ownerToken: s.ownerToken });
    }

    if (p === '/api/r' && m === 'POST') {
      const room = createRoom();
      return send(res, 201, { id: room.id });
    }

    const rm = p.match(/^\/api\/r\/([A-Za-z0-9_-]{22})\/(events|send)$/);
    if (rm) {
      const room = rooms.get(rm[1]);
      if (!room) return fail(res, 404, 'This session has ended');

      // Long-lived stream of relay events for one connected device.
      if (rm[2] === 'events' && m === 'GET') {
        if (room.peers.size >= ROOM_MAX_PEERS) return fail(res, 429, 'Too many devices in this session');
        clearTimeout(room.timer);
        const peerId = newId(6);
        const token = newId(18);
        res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': 'text/plain; charset=utf-8', 'X-Accel-Buffering': 'no' });
        res.write(`hi ${peerId} ${token} ${[...room.peers.keys()].join(',') || '-'}\n`);
        roomBroadcast(room, `join ${peerId}\n`);
        room.peers.set(peerId, { res, token });
        const beat = setInterval(() => res.write(':\n'), 15000);
        res.on('close', () => {
          clearInterval(beat);
          if (room.peers.get(peerId)?.res !== res) return;
          room.peers.delete(peerId);
          roomBroadcast(room, `leave ${peerId}\n`);
          if (!room.peers.size && rooms.has(room.id)) room.timer = setTimeout(() => closeRoom(room), ROOM_EMPTY_MS);
        });
        return;
      }

      // Relay one sealed message to every other device (or a single one with ?to=).
      if (rm[2] === 'send' && m === 'POST') {
        const from = req.headers['x-peer'];
        const peer = room.peers.get(from);
        const token = req.headers['x-peer-token'];
        if (!peer || typeof token !== 'string' || token.length !== peer.token.length ||
            !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(peer.token))) return fail(res, 403, 'Forbidden');
        const body = (await readBody(req, ROOM_MAX_MSG)).toString();
        if (!/^[A-Za-z0-9_-]+$/.test(body)) return fail(res, 400, 'Bad message');
        const to = url.searchParams.get('to');
        roomBroadcast(room, `msg ${from} ${body}\n`, from, to);
        return send(res, 200, { ok: true });
      }
      return fail(res, 405, 'Method not allowed');
    }

    if (p === '/api/pair' && m === 'POST') {
      const pair = createPair();
      if (!pair) return fail(res, 503, 'Too many pairing codes in use — try again shortly');
      return send(res, 201, { slot: pair.slot, token: pair.tokens.host, ttl: PAIR_TTL_MS });
    }

    const pm = p.match(/^\/api\/pair\/(\d{1,4})(?:\/(claim|send|recv))?$/);
    if (pm) {
      const pair = pairs.get(pm[1]);
      if (!pair) return fail(res, 404, 'That code doesn’t exist or has expired');
      const action = pm[2];

      // One guest per code: a second claim (e.g. someone guessing) is refused outright.
      if (action === 'claim' && m === 'POST') {
        if (pair.tokens.guest) return fail(res, 409, 'That code has already been used — ask for a new one');
        pair.tokens.guest = newId(18);
        return send(res, 200, { token: pair.tokens.guest });
      }

      const role = pairRole(req, pair);
      if (!role) return fail(res, 403, 'Forbidden');
      const other = role === 'host' ? 'guest' : 'host';

      if (action === 'send' && m === 'POST') {
        const body = (await readBody(req, PAIR_MAX_MSG)).toString();
        const w = pair.waiter[other];
        if (w) { pair.waiter[other] = null; clearTimeout(w.timer); send(w.res, 200, body); }
        else pair.queue[other].push(body);
        return send(res, 200, { ok: true });
      }

      if (action === 'recv' && m === 'GET') {
        if (pair.queue[role].length) return send(res, 200, pair.queue[role].shift());
        if (pair.waiter[role]) { clearTimeout(pair.waiter[role].timer); fail(pair.waiter[role].res, 409, 'Superseded'); }
        const w = { res, timer: setTimeout(() => { if (pair.waiter[role] === w) pair.waiter[role] = null; send(res, 204, ''); }, PAIR_WAIT_MS) };
        pair.waiter[role] = w;
        res.on('close', () => { if (pair.waiter[role] === w) { clearTimeout(w.timer); pair.waiter[role] = null; } });
        return;
      }

      if (!action && m === 'DELETE') {
        closePair(pair);
        return send(res, 200, { ok: true });
      }
      return fail(res, 405, 'Method not allowed');
    }

    const sm = p.match(/^\/api\/s\/([A-Za-z0-9_-]{22})(?:\/(c|m|a|w)(?:\/(\d{1,12}))?)?$/);
    if (sm) {
      const share = shares.get(sm[1]);
      // Same response for "never existed" and "expired" — reveals nothing.
      if (!share) return fail(res, 404, 'This share does not exist or has expired');
      const kind = sm[2];
      const index = sm[3] !== undefined ? parseInt(sm[3], 10) : undefined;

      if (!kind && m === 'GET') {
        const info = publicInfo(share);
        if (isOwner(req, share)) Object.assign(info, { opens: share.opens, downloads: share.downloads, senderOnline: !!share.sender });
        return send(res, 200, info);
      }

      if (!kind && m === 'DELETE') {
        // Owners can revoke anytime; recipients may burn a burn-after-reading share.
        if (!isOwner(req, share) && !(share.burn && share.sealed)) return fail(res, 403, 'Forbidden');
        destroyShare(share);
        return send(res, 200, { ok: true });
      }

      // Live shares: the sender's tab holds this channel open and is told which blocks to send.
      if (kind === 'w' && m === 'GET') {
        if (!share.live || !isOwner(req, share)) return fail(res, 403, 'Forbidden');
        if (share.sender) share.sender.end();
        clearTimeout(share.orphanTimer);
        res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': 'text/plain; charset=utf-8', 'X-Accel-Buffering': 'no' });
        res.write('ready\n');
        share.sender = res;
        const beat = setInterval(() => res.write(':\n'), 15000);
        res.on('close', () => {
          clearInterval(beat);
          if (share.sender !== res) return;
          share.sender = null;
          if (shares.has(share.id)) share.orphanTimer = setTimeout(() => destroyShare(share), LIVE_GRACE_MS);
        });
        return;
      }

      // Live shares: the sender answers a block request; we pipe it straight to the recipient.
      if (kind === 'c' && m === 'PUT' && index !== undefined && share.live) {
        if (!isOwner(req, share)) return fail(res, 403, 'Forbidden');
        const pend = share.pending.get(url.searchParams.get('r') || '');
        if (!pend || pend.index !== index) { req.resume(); return fail(res, 410, 'Request no longer pending'); }
        if (parseInt(req.headers['content-length'], 10) !== MAX_CHUNK_BODY) { req.resume(); return fail(res, 400, 'Chunks must be padded to full size'); }
        share.pending.delete(url.searchParams.get('r'));
        clearTimeout(pend.timer);
        pend.res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': 'application/octet-stream', 'Content-Length': MAX_CHUNK_BODY });
        pend.res.on('error', () => {});
        req.pipe(pend.res);
        req.on('end', () => send(res, 200, { ok: true }));
        req.on('error', () => pend.res.destroy());
        return;
      }

      // Upload a ciphertext chunk.
      if (kind === 'c' && m === 'PUT' && index !== undefined) {
        if (!isOwner(req, share)) return fail(res, 403, 'Forbidden');
        if (share.sealed) return fail(res, 409, 'Share is sealed');
        const body = await readBody(req, MAX_CHUNK_BODY);
        if (body.length !== MAX_CHUNK_BODY) return fail(res, 400, 'Chunks must be padded to full size');
        if (storedBytes + body.length > MAX_STORE_BYTES) return fail(res, 507, 'Host memory budget exhausted');
        if (!shares.has(share.id)) return fail(res, 404, 'Share expired');
        const prev = share.chunks[index];
        if (prev) { storedBytes -= prev.length; share.bytes -= prev.length; }
        share.chunks[index] = body;
        share.bytes += body.length;
        storedBytes += body.length;
        share.expiresAt = Date.now() + UPLOAD_IDLE_MS;
        return send(res, 200, { ok: true });
      }

      // Upload encrypted manifest — this seals the share.
      if (kind === 'm' && m === 'PUT') {
        if (!isOwner(req, share)) return fail(res, 403, 'Forbidden');
        if (share.sealed) return fail(res, 409, 'Share is sealed');
        const count = parseInt(req.headers['x-chunk-count'], 10);
        if (!(count >= 0)) return fail(res, 400, 'Missing chunk count');
        if (share.live) share.chunkCount = count;
        else if (count !== share.chunks.length) return fail(res, 400, 'Chunk count mismatch');
        if (!share.live) for (let i = 0; i < count; i++) if (!share.chunks[i]) return fail(res, 400, `Missing chunk ${i}`);
        const body = await readBody(req, MAX_MANIFEST_BODY);
        share.manifest = body;
        share.bytes += body.length;
        storedBytes += body.length;
        share.sealed = true;
        share.expiresAt = Date.now() + share.ttlMs;
        return send(res, 200, publicInfo(share));
      }

      if (kind === 'm' && m === 'GET') {
        if (!share.sealed) return fail(res, 404, 'This share does not exist or has expired');
        share.opens++;
        return send(res, 200, share.manifest, 'application/octet-stream');
      }

      // Recipient confirms a completed save (used for the sender's status display only).
      if (kind === 'a' && m === 'POST') {
        if (!share.sealed) return fail(res, 404, 'Not found');
        share.downloads++;
        return send(res, 200, { ok: true });
      }

      if (kind === 'c' && m === 'GET' && index !== undefined && share.live) {
        if (!share.sealed || index >= share.chunkCount) return fail(res, 404, 'Not found');
        if (!share.sender) return fail(res, 503, 'The sender is offline — their LocShare tab must stay open');
        const reqId = newId(9);
        const timer = setTimeout(() => { share.pending.delete(reqId); if (!res.headersSent) fail(res, 504, 'The sender did not respond'); }, LIVE_WAIT_MS);
        share.pending.set(reqId, { index, res, timer });
        res.on('close', () => { if (share.pending.get(reqId)?.res === res) { clearTimeout(timer); share.pending.delete(reqId); } });
        share.sender.write(`need ${reqId} ${index}\n`);
        return;
      }

      if (kind === 'c' && m === 'GET' && index !== undefined) {
        if (!share.sealed || !share.chunks[index]) return fail(res, 404, 'Not found');
        return send(res, 200, share.chunks[index], 'application/octet-stream');
      }

      return fail(res, 405, 'Method not allowed');
    }

    if (p.startsWith('/api/')) return fail(res, 404, 'Not found');

    // ---- static ----------------------------------------------------------
    if (m !== 'GET' && m !== 'HEAD') return fail(res, 405, 'Method not allowed');
    if (p.startsWith('/vendor/')) {
      const f = VENDOR[p.slice(8)];
      return f ? serveFile(res, f) : fail(res, 404, 'Not found');
    }
    // Receiver links look like /r/<id>#<key>; they load the same single-page app.
    if (p === '/' || /^\/[rp]\/[A-Za-z0-9_-]{22}$/.test(p)) return serveFile(res, path.join(PUBLIC_DIR, 'index.html'));
    const file = path.normalize(path.join(PUBLIC_DIR, p));
    if (!file.startsWith(PUBLIC_DIR + path.sep)) return fail(res, 404, 'Not found');
    return serveFile(res, file);
  } catch (err) {
    if (!res.headersSent) fail(res, err.status || 400, err.status ? err.message : 'Bad request');
  }
}

// ---------------------------------------------------------------- start
let tlsInfo = null;
function tlsOptions() {
  if (TLS_CERT && TLS_KEY) return { cert: fs.readFileSync(TLS_CERT), key: fs.readFileSync(TLS_KEY) };
  tlsInfo = require('./tls').selfSigned(lanAddresses().map((a) => a.address), path.join(__dirname, '.locshare'));
  return { cert: tlsInfo.cert, key: tlsInfo.key };
}
const server = USE_TLS ? https.createServer(tlsOptions(), handle) : http.createServer(handle);

server.requestTimeout = 5 * 60 * 1000;

server.listen(PORT, HOST, () => {
  const proto = USE_TLS ? 'https' : 'http';
  const c = (s, n) => (process.stdout.isTTY ? `\x1b[${n}m${s}\x1b[0m` : s);
  console.log(`\n  ${c('LocShare', '1;35')}  ${c('private file sharing on your network', '2')}\n`);
  console.log(`  ${c('Local:', '2')}    ${proto}://localhost:${PORT}`);
  for (const a of lanAddresses()) console.log(`  ${c('Network:', '2')}  ${c(`${proto}://${a.address}:${PORT}`, '36')}  ${c(a.name, '2')}`);
  console.log(`\n  ${c('End-to-end encrypted · RAM only · no logs', '2')}\n`);
  if (tlsInfo) {
    console.log(`  ${c('HTTPS with a self-signed certificate', '33')}${tlsInfo.created ? ' (new)' : ''}. Browsers will warn once per device —`);
    console.log(`  choose ${c('Advanced → Proceed', '1')} after checking this fingerprint matches the one in the warning:`);
    console.log(`  ${c(tlsInfo.fingerprint, '2')}\n`);
  } else if (!USE_TLS) {
    console.log(`  ${c('Tip:', '2')} run ${c('npm run https', '1')} to let browsers save straight into folders you choose.\n`);
  }
});

function shutdown() {
  for (const pr of [...pairs.values()]) closePair(pr);
  for (const r of [...rooms.values()]) closeRoom(r);
  for (const s of [...shares.values()]) destroyShare(s);
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
