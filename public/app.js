/* LocShare client — all encryption and decryption happens here, in the browser. */
(() => {
  'use strict';

  // ============================================================ utilities
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];
  const h = (tag, props = {}, ...kids) => {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (k === 'class') el.className = v;
      else if (k === 'style') el.style.cssText = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (k === 'html') el.innerHTML = v; // only ever used with static strings
      else el.setAttribute(k, v);
    }
    for (const kid of kids.flat()) if (kid != null) el.append(kid);
    return el;
  };

  const b64u = {
    enc(bytes) {
      let s = '';
      for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
      return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    },
    dec(str) {
      const s = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
      const out = new Uint8Array(s.length);
      for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
      return out;
    },
  };

  function fmtBytes(n) {
    if (n < 1024) return `${n} B`;
    const u = ['KB', 'MB', 'GB', 'TB'];
    let i = -1;
    do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
    return `${n.toFixed(n < 10 ? 1 : 0)} ${u[i]}`;
  }
  function fmtLeft(ms) {
    const s = Math.max(0, Math.round(ms / 1000));
    if (s >= 3600) return `${Math.floor(s / 3600)}h${String(Math.floor((s % 3600) / 60)).padStart(2, '0')}`;
    if (s >= 60) return `${Math.floor(s / 60)}m`;
    return `${s}s`;
  }
  const ttlLabel = (m) => (m >= 60 ? `${m / 60}h` : `${m}m`);

  // Average throughput since the first bytes moved. Quiet until a transfer is actually moving.
  function pace() {
    let t0 = 0;
    return (bytes) => {
      if (!(bytes > 0)) return '';
      if (!t0) t0 = performance.now();
      if (bytes < 256 * 1024) return '';
      const dt = (performance.now() - t0) / 1000;
      if (dt < 0.5) return '';
      return `${fmtBytes(bytes / dt)}/s`;
    };
  }

  function toast(msg, kind = '') {
    const t = h('div', { class: `toast ${kind}` }, msg);
    $('#toasts').append(t);
    setTimeout(() => { t.classList.add('out'); t.addEventListener('animationend', () => t.remove()); }, 3200);
  }

  async function api(path, opts = {}) {
    const res = await fetch(path, { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer', ...opts });
    if (!res.ok) {
      let msg = `Request failed (${res.status})`;
      try { msg = (await res.json()).error || msg; } catch { /* binary */ }
      throw Object.assign(new Error(msg), { status: res.status });
    }
    return res;
  }

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  // A received path is untrusted: keep it strictly relative, drop "." / "..", and strip
  // characters file systems reject, so nothing can ever be written outside the chosen folder.
  function safeSegments(path) {
    return String(path || '')
      .split(/[\\/]+/)
      .map((seg) => seg.replace(/[\x00-\x1f<>:"|?*]/g, '_').trim().slice(0, 200))
      .filter((seg) => seg && seg !== '.' && seg !== '..')
      .map((seg) => (/^\.+$/.test(seg) ? '_' : seg)) // all-dot names are invalid on Windows
      .slice(-48);
  }
  const topOf = (path) => { const segs = safeSegments(path); return segs.length > 1 ? segs[0] : null; };

  // Normalise File lists / {file, path} items into {file, path}.
  const asItems = (list) => [...list].map((x) => (x instanceof File ? { file: x, path: x.webkitRelativePath || x.name } : x));

  // Group items into top-level folders and loose files, preserving order.
  function groupItems(items, pathOf, sizeOf) {
    const groups = [];
    const byTop = new Map();
    items.forEach((it, i) => {
      const top = topOf(pathOf(it));
      if (!top) { groups.push({ kind: 'file', items: [it], idx: [i] }); return; }
      let g = byTop.get(top);
      if (!g) { g = { kind: 'folder', name: top, items: [], idx: [], size: 0 }; byTop.set(top, g); groups.push(g); }
      g.items.push(it); g.idx.push(i); g.size += sizeOf(it);
    });
    return groups;
  }
  const describe = (groups) => {
    const folders = groups.filter((g) => g.kind === 'folder').length;
    const files = groups.length - folders;
    const part = (n, w) => `${n} ${w}${n > 1 ? 's' : ''}`;
    return [folders && part(folders, 'folder'), files && part(files, 'file')].filter(Boolean).join(' and ');
  };

  // Walk dropped folders recursively. Entries must be grabbed synchronously inside the drop event.
  function entriesFromDrop(dt) {
    let entries = [];
    try { entries = [...(dt?.items || [])].filter((i) => i.kind === 'file').map((i) => i.webkitGetAsEntry?.()).filter(Boolean); } catch { entries = []; }
    return entries.length ? entries : null;
  }
  // Browsers also list a dropped or pasted *folder* in `.files` as a fake, unreadable file
  // (0 B on Windows, 4 KB on Linux/macOS). Spot those so a folder is never shared as an empty file.
  async function isFolderStub(f) {
    if (f.type) return false;
    try { await f.slice(0, 1).arrayBuffer(); } catch { return true; }
    return f.size === 0 && !/\.[^./]+$/.test(f.name);
  }

  async function walkEntries(entries, onProgress) {
    const items = [];
    const dirs = [];
    const failed = [];
    let bytes = 0;
    let last = 0;
    const tick = () => {
      const now = performance.now();
      if (now - last > 150) { last = now; onProgress?.(items.length, bytes); }
    };
    const fileOf = (entry) => new Promise((res, rej) => entry.file(res, rej));
    const listDir = async (dir) => {
      const reader = dir.createReader();
      const kids = [];
      for (;;) { // readEntries returns at most ~100 entries per call
        const batch = await new Promise((res, rej) => reader.readEntries(res, rej));
        if (!batch.length) return kids;
        kids.push(...batch);
      }
    };
    async function walk(entry, prefix) {
      if (entry.isFile) {
        // Unreadable files (no permission, online-only cloud placeholders…) are skipped, not fatal.
        try { const file = await fileOf(entry); items.push({ file, path: prefix + file.name }); bytes += file.size; tick(); }
        catch { failed.push(prefix + entry.name); }
        return;
      }
      if (!entry.isDirectory) return;
      const here = prefix + entry.name;
      let kids;
      try { kids = await listDir(entry); } catch { failed.push(here + '/'); return; }
      if (!kids.length) { dirs.push(here); return; }
      const files = kids.filter((k) => k.isFile);
      for (let i = 0; i < files.length; i += 64) await Promise.all(files.slice(i, i + 64).map((k) => walk(k, here + '/')));
      for (const k of kids) if (k.isDirectory) await walk(k, here + '/');
    }
    for (const e of entries) await walk(e, '');
    items.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    onProgress?.(items.length, bytes);
    return { items, dirs, failed, stubs: [] };
  }

  // Everything that arrives by drag & drop or paste goes through here.
  async function droppedItems(dt, onProgress) {
    const entries = entriesFromDrop(dt); // must run before the first await
    if (entries) return walkEntries(entries, onProgress);
    const files = [...(dt?.files || [])];
    const items = [];
    const stubs = [];
    for (const f of files) (await isFolderStub(f) ? stubs : items).push(f);
    return { items: asItems(items), dirs: [], failed: [], stubs: stubs.map((f) => f.name) };
  }

  // Tell people about anything that couldn't come along.
  function reportDropIssues({ items, dirs, failed, stubs }, how) {
    if (stubs.length) {
      const name = `“${stubs[0]}”${stubs.length > 1 ? ` and ${stubs.length - 1} more` : ''}`;
      toast(how === 'paste'
        ? `${name} is a folder — browsers can’t paste folders. Drag it in, or use “choose a folder”.`
        : `This browser didn’t let LocShare look inside ${name}. Use “choose a folder” instead.`, 'err');
    }
    if (failed.length) toast(`Skipped ${failed.length.toLocaleString()} item${failed.length > 1 ? 's' : ''} that couldn’t be read (no permission, or online-only cloud files)`, 'err');
    return items.length + dirs.length > 0;
  }

  // A toast that stays up and updates while a big folder is being read.
  function liveToast() {
    const t = h('div', { class: 'toast live' }, 'Reading…');
    $('#toasts').append(t);
    return {
      set: (text) => { t.textContent = text; },
      done: () => { t.classList.add('out'); t.addEventListener('animationend', () => t.remove()); },
    };
  }
  const readingText = (n, bytes) => `Reading folder… ${n.toLocaleString()} file${n === 1 ? '' : 's'} · ${fmtBytes(bytes)}`;

  async function pool(count, limit, worker) {
    let next = 0;
    const run = async () => { while (next < count) { const i = next++; await worker(i); } };
    await Promise.all(Array.from({ length: Math.min(limit, count) }, run));
  }

  function saveBlob(blob, name) {
    const url = URL.createObjectURL(blob);
    const a = h('a', { href: url, download: name, rel: 'noopener' });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
  }

  // ============================================================ crypto
  // File blocks are sealed off the main thread, one worker per core.
  // HTTPS pages use AES-256-GCM (hardware). Plain HTTP, where WebCrypto is unavailable, uses
  // XSalsa20-Poly1305. Notes, manifests and room messages stay on NaCl here — they're tiny and
  // their nonce is random, not derived from a block index.
  const NONCE = 24;
  let CHUNK = 1024 * 1024;

  function chunkNonce(prefix, index) {
    const n = new Uint8Array(NONCE);
    n.set(prefix, 0);
    new DataView(n.buffer).setBigUint64(16, BigInt(index));
    return n;
  }

  function seal(plain, nonce, key) {
    const box = nacl.secretbox(plain, nonce, key);
    const out = new Uint8Array(NONCE + box.length);
    out.set(nonce, 0);
    out.set(box, NONCE);
    return out;
  }

  function sealManifest(obj, key) {
    const json = new TextEncoder().encode(JSON.stringify(obj));
    // Pad to a 4 KiB boundary so the manifest's size doesn't reveal file names or count.
    const padded = new Uint8Array(Math.ceil((json.length + 4) / 4096) * 4096);
    new DataView(padded.buffer).setUint32(0, json.length);
    padded.set(json, 4);
    return seal(padded, nacl.randomBytes(NONCE), key);
  }

  function openManifest(bytes, key) {
    const plain = nacl.secretbox.open(bytes.subarray(NONCE), bytes.subarray(0, NONCE), key);
    if (!plain) return null;
    const len = new DataView(plain.buffer, plain.byteOffset).getUint32(0);
    return JSON.parse(new TextDecoder().decode(plain.subarray(4, 4 + len)));
  }

  function makeSemaphore(max) {
    let used = 0;
    const q = [];
    return {
      acquire() {
        if (used < max) { used++; return Promise.resolve(); }
        return new Promise((resolve) => q.push(resolve));
      },
      release() {
        const next = q.shift();
        if (next) next();
        else used--;
      },
    };
  }

  // File-block cipher. The same key bytes feed either algorithm; the manifest records which.
  const blocks = (() => {
    const useAes = location.protocol === 'https:' && !!(globalThis.crypto && crypto.subtle);
    const cipher = useAes ? 'aes-256-gcm' : 'xsalsa20poly1305';
    const cores = Math.min(4, navigator.hardwareConcurrency || 2);
    const slots = makeSemaphore(cores * 2);
    const workers = [];
    const pending = new Map();
    let seq = 0;
    let rr = 0;
    let broken = false;

    function failWorker(w, err) {
      for (const [id, job] of pending) {
        if (job.w === w) { pending.delete(id); job.reject(err); }
      }
    }
    try {
      for (let i = 0; i < cores; i++) {
        const w = new Worker('/crypto-worker.js');
        w.onmessage = (e) => {
          const job = pending.get(e.data.id);
          if (!job) return;
          pending.delete(e.data.id);
          if (e.data.error) {
            const error = new Error(e.data.error === 'tamper' ? 'Integrity check failed — data was tampered with' : e.data.error);
            if (e.data.error === 'tamper') error.fatal = true;
            job.reject(error);
          } else job.resolve(new Uint8Array(e.data.out, e.data.off || 0, e.data.len));
        };
        w.onerror = () => { broken = true; failWorker(w, new Error('Encryption worker failed')); };
        workers.push(w);
      }
    } catch { broken = true; }

    const aesKeys = new WeakMap();
    function aesIv(prefix, index) {
      const iv = new Uint8Array(12);
      iv.set(prefix.subarray(0, 4), 0);
      new DataView(iv.buffer).setBigUint64(4, BigInt(index));
      return iv;
    }
    async function aesKey(raw) {
      let p = aesKeys.get(raw);
      if (!p) {
        p = crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
        aesKeys.set(raw, p);
      }
      return p;
    }
    async function localRun(op, data, index, key, prefix, which) {
      if (which === 'aes-256-gcm') {
        const iv = aesIv(prefix, index);
        const k = await aesKey(key);
        if (op === 'seal') {
          const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, data));
          data.fill(0);
          const out = new Uint8Array(NONCE + ct.length);
          out.set(iv, 0);
          out.set(ct, NONCE);
          return out;
        }
        try {
          return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, k, data.subarray(NONCE)));
        } catch {
          throw Object.assign(new Error('Integrity check failed — data was tampered with'), { fatal: true });
        }
      }
      if (op === 'seal') {
        const out = seal(data, chunkNonce(prefix, index), key);
        data.fill(0);
        return out;
      }
      const plain = nacl.secretbox.open(data.subarray(NONCE), chunkNonce(prefix, index), key);
      if (!plain) throw Object.assign(new Error('Integrity check failed — data was tampered with'), { fatal: true });
      return plain;
    }
    function call(op, bytes, index, key, prefix, which) {
      if (broken || !workers.length) return localRun(op, bytes, index, key, prefix, which);
      const w = workers[rr++ % workers.length];
      const id = ++seq;
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject, w });
        try {
          const msg = { id, op, cipher: which, index, key, prefix };
          if (bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength) {
            msg.data = bytes.buffer;
            w.postMessage(msg, [bytes.buffer]);
          } else {
            msg.data = bytes;
            w.postMessage(msg);
          }
        } catch (err) {
          pending.delete(id);
          reject(err);
        }
      });
    }
    async function run(op, bytes, index, key, prefix, which) {
      await slots.acquire();
      try { return await call(op, bytes, index, key, prefix, which); }
      finally { slots.release(); }
    }
    return {
      cipher,
      seal: (plain, index, key, prefix) => run('seal', plain, index, key, prefix, cipher),
      open: (boxed, index, key, prefix, which) => run('open', boxed, index, key, prefix, which || cipher),
    };
  })();

  function chooseChunk(total) {
    const sizes = (info.chunkSizes?.length ? info.chunkSizes : [info.chunkSize || CHUNK]).slice().sort((a, b) => a - b);
    if (total >= 32 * 1024 * 1024 && sizes.length > 1) return sizes[sizes.length - 1];
    return sizes[0];
  }
  // Must match the server's maxBatch(): several chunks per request, about 16 MiB.
  function maxBatch(chunkBody) {
    const target = info.batchBytes || (16 * 1024 * 1024 + 64 * 40);
    const cap = info.batchCap || 8;
    return Math.max(1, Math.min(cap, Math.floor(target / chunkBody)));
  }

  // CRC-32 for the zip writer
  const CRC_TABLE = (() => {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      t[n] = c >>> 0;
    }
    return t;
  })();
  function crc32(buf, crc = 0) {
    crc = ~crc >>> 0;
    for (let i = 0; i < buf.length; i++) crc = CRC_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
    return ~crc >>> 0;
  }

  // ---- output sinks: where decrypted bytes go, without ever holding a whole file in JS memory.
  // With the File System Access API (Chromium over HTTPS/localhost) bytes stream straight to disk.
  // Otherwise they're gathered into Blobs in batches, which browsers can page out of RAM.
  async function openSink(name, type) {
    if (window.showSaveFilePicker) {
      try {
        const handle = await window.showSaveFilePicker({ suggestedName: name });
        const w = await handle.createWritable();
        return { write: (d) => w.write(d), close: () => w.close(), abort: () => w.abort().catch(() => {}) };
      } catch (err) {
        if (err.name === 'AbortError') throw err; // user cancelled the dialog
      }
    }
    const blobs = [];
    let parts = [];
    let size = 0;
    return {
      write(d) {
        parts.push(d);
        size += d.byteLength ?? d.size;
        if (size >= 32 * 1024 * 1024) { blobs.push(new Blob(parts)); parts = []; size = 0; }
      },
      close() { blobs.push(new Blob(parts)); saveBlob(new Blob(blobs, { type: type || 'application/octet-stream' }), name); },
      abort() { blobs.length = 0; parts = []; },
    };
  }

  // Streaming "stored" zip writer with ZIP64 — no size or file-count limits.
  // CRCs go in data descriptors after each file, so nothing needs to be buffered.
  function zipWriter(sink) {
    const enc = new TextEncoder();
    const MAX32 = 0xffffffff;
    const files = [];
    const used = new Set();
    let offset = 0;
    const d = new Date();
    const time = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1);
    const date = ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
    const put = async (data) => { await sink.write(data); offset += data.byteLength ?? data.size; };
    const view = (n) => { const b = new Uint8Array(n); return [b, new DataView(b.buffer)]; };
    const u64 = (dv, at, v) => dv.setBigUint64(at, BigInt(v), true);

    return {
      async add(rawName, size, writeData) {
        const isDir = rawName.endsWith('/');
        const clean = safeSegments(rawName).join('/') || 'file';
        let name = clean + (isDir ? '/' : '');
        for (let i = 2; used.has(name); i++) name = clean.replace(/(\.[^./]*)?$/, ` (${i})$1`) + (isDir ? '/' : '');
        used.add(name);
        const nb = enc.encode(name);
        const big = size >= MAX32;
        const start = offset;
        const [lh, l] = view(30 + nb.length + (big ? 20 : 0));
        l.setUint32(0, 0x04034b50, true); l.setUint16(4, big ? 45 : 20, true); l.setUint16(6, 0x0808, true);
        l.setUint16(10, time, true); l.setUint16(12, date, true);
        l.setUint32(18, big ? MAX32 : size, true); l.setUint32(22, big ? MAX32 : size, true);
        l.setUint16(26, nb.length, true); l.setUint16(28, big ? 20 : 0, true);
        lh.set(nb, 30);
        if (big) { const x = 30 + nb.length; l.setUint16(x, 1, true); l.setUint16(x + 2, 16, true); u64(l, x + 4, size); u64(l, x + 12, size); }
        await put(lh);
        const crc = await writeData(put);
        const [dd, v] = view(big ? 24 : 16);
        v.setUint32(0, 0x08074b50, true); v.setUint32(4, crc, true);
        if (big) { u64(v, 8, size); u64(v, 16, size); } else { v.setUint32(8, size, true); v.setUint32(12, size, true); }
        await put(dd);
        files.push({ nb, size, crc, start, isDir });
      },
      async finish() {
        const cdStart = offset;
        for (const f of files) {
          const z = f.size >= MAX32 || f.start >= MAX32;
          const [ch, c] = view(46 + f.nb.length + (z ? 28 : 0));
          c.setUint32(0, 0x02014b50, true); c.setUint16(4, 45, true); c.setUint16(6, z ? 45 : 20, true); c.setUint16(8, 0x0808, true);
          c.setUint16(12, time, true); c.setUint16(14, date, true); c.setUint32(16, f.crc, true);
          c.setUint32(20, z ? MAX32 : f.size, true); c.setUint32(24, z ? MAX32 : f.size, true);
          c.setUint16(28, f.nb.length, true); c.setUint16(30, z ? 28 : 0, true); c.setUint32(42, z ? MAX32 : f.start, true);
          if (f.isDir) c.setUint32(38, 0x10, true); // MS-DOS directory attribute
          ch.set(f.nb, 46);
          if (z) { const x = 46 + f.nb.length; c.setUint16(x, 1, true); c.setUint16(x + 2, 24, true); u64(c, x + 4, f.size); u64(c, x + 12, f.size); u64(c, x + 20, f.start); }
          await put(ch);
        }
        const cdSize = offset - cdStart;
        const n = files.length;
        if (n >= 0xffff || cdStart >= MAX32 || cdSize >= MAX32 || files.some((f) => f.size >= MAX32 || f.start >= MAX32)) {
          const z64At = offset;
          const [r, e] = view(56 + 20);
          e.setUint32(0, 0x06064b50, true); u64(e, 4, 44); e.setUint16(12, 45, true); e.setUint16(14, 45, true);
          u64(e, 24, n); u64(e, 32, n); u64(e, 40, cdSize); u64(e, 48, cdStart);
          e.setUint32(56, 0x07064b50, true); u64(e, 64, z64At); e.setUint32(72, 1, true);
          await put(r);
        }
        const [end, e] = view(22);
        e.setUint32(0, 0x06054b50, true);
        e.setUint16(8, Math.min(n, 0xffff), true); e.setUint16(10, Math.min(n, 0xffff), true);
        e.setUint32(12, Math.min(cdSize, MAX32), true); e.setUint32(16, Math.min(cdStart, MAX32), true);
        await put(end);
        await sink.close();
      },
    };
  }

  // ============================================================ file visuals
  const KINDS = [
    { k: 'img', re: /^image\//, ext: /\.(png|jpe?g|gif|webp|avif|heic|svg|bmp)$/i, c: ['#f472b6', '#a855f7'] },
    { k: 'vid', re: /^video\//, ext: /\.(mp4|mov|mkv|webm|avi)$/i, c: ['#fb7185', '#f97316'] },
    { k: 'aud', re: /^audio\//, ext: /\.(mp3|wav|flac|ogg|m4a|aac)$/i, c: ['#22d3ee', '#3b82f6'] },
    { k: 'pdf', re: /pdf/, ext: /\.pdf$/i, c: ['#f43f5e', '#be123c'] },
    { k: 'zip', re: /zip|compressed|tar|rar|7z/, ext: /\.(zip|rar|7z|tar|gz|tgz|xz|bz2)$/i, c: ['#fbbf24', '#d97706'] },
    { k: 'code', re: /json|javascript|xml|x-sh/, ext: /\.(js|ts|py|go|rs|c|cpp|h|java|rb|php|sh|json|html|css|md|yml|yaml|toml)$/i, c: ['#34d399', '#059669'] },
    { k: 'doc', re: /text|word|document|sheet|presentation/, ext: /\.(txt|docx?|xlsx?|pptx?|odt|csv|rtf|key|pages|numbers)$/i, c: ['#60a5fa', '#6366f1'] },
  ];
  function folderIcon() {
    return h('div', { class: 'ficon folder', html: '<svg viewBox="0 0 24 24"><path d="M3 7.5A2.5 2.5 0 015.5 5h3.6l2 2.2h7.4A2.5 2.5 0 0121 9.7v7.8A2.5 2.5 0 0118.5 20h-13A2.5 2.5 0 013 17.5z"/></svg>' });
  }

  function kindOf(name, type) {
    return KINDS.find((k) => k.re.test(type || '') || k.ext.test(name)) || { k: 'file', c: ['#8b5cf6', '#4f46e5'] };
  }
  function fileIcon(name, type, thumbUrl) {
    const kind = kindOf(name, type);
    const ext = (name.match(/\.([a-z0-9]{1,4})$/i) || [, kind.k])[1];
    const el = h('div', { class: 'ficon', style: `--c1:${kind.c[0]};--c2:${kind.c[1]}` }, ext);
    if (thumbUrl) setThumb(el, thumbUrl);
    return el;
  }
  function setThumb(el, url) {
    const img = h('img', { alt: '', src: url });
    img.onload = () => { el.textContent = ''; el.append(img); };
  }

  const ICON = {
    chev: '<svg viewBox="0 0 24 24"><path d="M9 6l6 6-6 6"/></svg>',
    folderDl: '<svg viewBox="0 0 24 24"><path d="M3 7.5A2.5 2.5 0 015.5 5h3.6l2 2.2h7.4A2.5 2.5 0 0121 9.7v7.8A2.5 2.5 0 0118.5 20h-13A2.5 2.5 0 013 17.5z"/><path d="M12 10.5v6m0 0l-2.5-2.5M12 16.5l2.5-2.5"/></svg>',
    copy: '<svg viewBox="0 0 24 24"><rect x="8" y="8" width="12" height="12" rx="3"/><path d="M16 8V6a2 2 0 00-2-2H6a2 2 0 00-2 2v8a2 2 0 002 2h2"/></svg>',
    x: '<svg viewBox="0 0 24 24"><path d="M6 6l12 12M18 6L6 18"/></svg>',
    dl: '<svg viewBox="0 0 24 24"><path d="M12 4v11m0 0l-4.5-4.5M12 15l4.5-4.5"/><path d="M5 19h14"/></svg>',
    ok: '<svg viewBox="0 0 24 24"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>',
    spin: '<svg viewBox="0 0 24 24"><path d="M12 3a9 9 0 109 9"><animateTransform attributeName="transform" type="rotate" from="0 12 12" to="360 12 12" dur="0.8s" repeatCount="indefinite"/></path></svg>',
  };

  const DEVICE_ICON = {
    phone: '<svg viewBox="0 0 24 24"><rect x="7" y="2.5" width="10" height="19" rx="2.5"/><path d="M11 18.5h2"/></svg>',
    tablet: '<svg viewBox="0 0 24 24"><rect x="4.5" y="2.5" width="15" height="19" rx="2.5"/><path d="M11 18.5h2"/></svg>',
    desktop: '<svg viewBox="0 0 24 24"><rect x="2.5" y="4" width="19" height="12.5" rx="2"/><path d="M8 20.5h8M12 16.5v4"/></svg>',
  };

  // ============================================================ view switching
  let currentView = null;
  function show(name) {
    const next = $(`[data-view="${name}"]`);
    if (currentView === next) return;
    const prev = currentView;
    currentView = next;
    if (prev) {
      prev.classList.remove('entering');
      prev.classList.add('leaving');
      setTimeout(() => { prev.classList.add('hidden'); prev.classList.remove('leaving'); }, 330);
    }
    const reveal = () => {
      next.classList.remove('hidden');
      next.classList.add('entering');
      $$('.card', next).forEach((c) => { c.style.animation = 'none'; void c.offsetWidth; c.style.animation = ''; });
      window.scrollTo({ top: 0, behavior: 'smooth' });
    };
    prev ? setTimeout(reveal, 180) : reveal();
  }

  // Cursor-tracking glow on cards
  document.addEventListener('pointermove', (e) => {
    const card = e.target.closest?.('.card.glow');
    if (!card) return;
    const r = card.getBoundingClientRect();
    card.style.setProperty('--mx', `${e.clientX - r.left}px`);
    card.style.setProperty('--my', `${e.clientY - r.top}px`);
  }, { passive: true });

  // Privacy sheet
  const dlg = $('#privacyDlg');
  $$('.facts li').forEach((li, i) => li.style.setProperty('--i', i));
  $('#privacyBtn').addEventListener('click', () => dlg.showModal());
  $('#privacyClose').addEventListener('click', () => dlg.close());
  dlg.addEventListener('click', (e) => { if (e.target === dlg) dlg.close(); });

  // ============================================================ server info
  let info = {
    chunkSize: CHUNK, chunkSizes: [CHUNK, 4 * CHUNK], batchBytes: 16 * 1024 * 1024 + 64 * 40, batchCap: 8,
    ttlChoices: [5, 15, 60, 360, 1440], origins: [],
  };
  const infoReady = api('/api/info').then((r) => r.json()).then((i) => { info = i; CHUNK = i.chunkSize; }).catch(() => {});

  const isLoopback = /^(localhost|127\.|\[::1\]$)/.test(location.hostname);
  function shareOrigins() {
    const list = [];
    if (!isLoopback) list.push({ name: 'This address', origin: location.origin });
    for (const o of info.origins) if (!list.some((x) => x.origin === o.origin)) list.push(o);
    if (!list.length) list.push({ name: 'This device', origin: location.origin });
    return list;
  }

  // ============================================================ SEND
  const state = { files: [], mode: 'files', ttl: 60, burn: false, busy: false };
  const mine = []; // active shares created in this tab — memory only, never persisted

  const drop = $('#drop');
  const fileInput = $('#fileInput');
  const fileList = $('#fileList');
  const shareBtn = $('#shareBtn');

  // mode tabs
  $('#modeSeg').addEventListener('click', (e) => {
    const btn = e.target.closest('.seg-btn');
    if (!btn) return;
    state.mode = btn.dataset.mode;
    $('#modeSeg').dataset.mode = state.mode;
    $$('.seg-btn').forEach((b) => { b.classList.toggle('active', b === btn); b.setAttribute('aria-selected', b === btn); });
    $$('.pane').forEach((p) => p.classList.toggle('hidden', p.dataset.pane !== state.mode));
    if (state.mode === 'note') $('#noteInput').focus();
    refreshSummary();
  });

  // TTL chips
  async function buildChips() {
    await infoReady;
    const wrap = $('#ttlChips');
    for (const m of info.ttlChoices) {
      wrap.append(h('button', { class: `chip${m === state.ttl ? ' active' : ''}`, type: 'button', 'data-ttl': m }, ttlLabel(m)));
    }
    wrap.addEventListener('click', (e) => {
      const c = e.target.closest('.chip');
      if (!c) return;
      state.ttl = +c.dataset.ttl;
      $$('.chip', wrap).forEach((x) => x.classList.toggle('active', x === c));
      movePill();
    });
    requestAnimationFrame(movePill);
    window.addEventListener('resize', movePill);
  }
  function movePill() {
    const a = $('#ttlChips .chip.active');
    const pill = $('#ttlChips .chip-pill');
    if (!a) return;
    pill.style.width = `${a.offsetWidth}px`;
    pill.style.transform = `translateX(${a.offsetLeft}px)`;
  }
  buildChips();

  $('#burnToggle').addEventListener('change', (e) => { state.burn = e.target.checked; });

  // file picking
  const folderInput = $('#folderInput');
  fileInput.addEventListener('change', () => { addFiles(fileInput.files); fileInput.value = ''; });
  folderInput.addEventListener('change', () => { addFiles(folderInput.files); folderInput.value = ''; });
  drop.addEventListener('click', (e) => (e.target.closest('[data-pick="folder"]') ? folderInput : fileInput).click());
  drop.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); } });
  if (!('webkitdirectory' in folderInput)) $$('[data-pick="folder"]').forEach((el) => el.remove());
  let dragDepth = 0;
  const dropTarget = () => (currentView?.id === 'view-room' ? $('#roomView') : drop);
  window.addEventListener('dragenter', (e) => {
    if (!['view-send', 'view-room'].includes(currentView?.id)) return;
    e.preventDefault(); dragDepth++; dropTarget().classList.add('over');
  });
  window.addEventListener('dragleave', () => { if (--dragDepth <= 0) { dragDepth = 0; drop.classList.remove('over'); $('#roomView').classList.remove('over'); } });
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', (e) => {
    e.preventDefault();
    dragDepth = 0;
    drop.classList.remove('over');
    $('#roomView').classList.remove('over');
    if (!['view-send', 'view-room'].includes(currentView?.id) || !e.dataTransfer?.files.length) return;
    const inRoom = currentView.id === 'view-room';
    if (!inRoom && state.mode !== 'files') $('[data-mode="files"]').click();
    takeIncoming(e.dataTransfer, inRoom, 'drop');
  });
  window.addEventListener('paste', (e) => {
    if (!['view-send', 'view-room'].includes(currentView?.id) || !e.clipboardData?.files.length) return;
    e.preventDefault();
    const inRoom = currentView.id === 'view-room';
    if (!inRoom && state.mode !== 'files') $('[data-mode="files"]').click();
    takeIncoming(e.clipboardData, inRoom, 'paste');
  });

  // Read dropped/pasted things (walking folders), with a live count for big folders.
  function takeIncoming(dt, inRoom, how) {
    let tip = null;
    const timer = setTimeout(() => { tip = liveToast(); }, 400); // only for reads that take a moment
    if (!inRoom) drop.classList.add('reading');
    droppedItems(dt, (n, bytes) => {
      tip?.set(readingText(n, bytes));
      if (!inRoom) $('#summary').textContent = readingText(n, bytes);
    }).then((res) => {
      if (!reportDropIssues(res, how)) return;
      if (inRoom) sendRoomFiles(res.items, res.dirs);
      else addFiles(res.items, res.dirs);
    }).catch((err) => toast(`Couldn’t read that: ${err.message}`, 'err'))
      .finally(() => {
        clearTimeout(timer);
        tip?.done();
        drop.classList.remove('reading');
        if (!inRoom) refreshSummary();
      });
  }

  // state.files holds {file, path} items; state.dirs holds empty folder paths.
  state.dirs = [];
  function addFiles(list, dirs = []) {
    if (state.busy) return;
    const start = fileList.children.length;
    const keyOf = (it) => `${it.path}\u0000${it.file.size}\u0000${it.file.lastModified}`;
    const seen = new Set(state.files.map(keyOf));
    const fresh = asItems(list).filter((it) => { const k = keyOf(it); if (seen.has(k)) return false; seen.add(k); return true; });
    for (const d of dirs) if (!state.dirs.includes(d)) state.dirs.push(d);
    state.files.push(...fresh);
    let n = 0;
    for (const g of groupItems(fresh, (it) => it.path, (it) => it.file.size)) {
      if (g.kind === 'file') {
        const it = g.items[0];
        const f = it.file;
        const thumb = kindOf(f.name, f.type).k === 'img' && f.size < 25e6 ? URL.createObjectURL(f) : null;
        const li = h('li', { class: 'file', style: `--i:${start + n++ - start}` },
          fileIcon(f.name, f.type, thumb),
          h('div', { class: 'fmeta' }, h('div', { class: 'fname', title: f.name }, f.name), h('div', { class: 'fsize' }, fmtBytes(f.size))),
          h('button', { class: 'x-btn', title: 'Remove', 'aria-label': `Remove ${f.name}`, html: ICON.x, onclick: () => removeItems((x) => x === it, li, thumb) }));
        fileList.append(li);
      } else {
        const existing = $(`[data-folder="${CSS.escape(g.name)}"]`, fileList);
        if (existing) { updateFolderRow(existing, g.name); continue; }
        const li = h('li', { class: 'file folder-row', 'data-folder': g.name, style: `--i:${n++}` },
          folderIcon(),
          h('div', { class: 'fmeta' }, h('div', { class: 'fname', title: g.name }, g.name), h('div', { class: 'fsize' })),
          h('button', { class: 'x-btn', title: 'Remove folder', 'aria-label': `Remove folder ${g.name}`, html: ICON.x,
            onclick: () => removeItems((x) => topOf(x.path) === g.name, li, null, g.name) }));
        fileList.append(li);
        updateFolderRow(li, g.name);
      }
    }
    // Empty top-level folders (dropped on their own) get a row too.
    for (const d of dirs) {
      const top = safeSegments(d)[0];
      if (!top || $(`[data-folder="${CSS.escape(top)}"]`, fileList)) continue;
      const li = h('li', { class: 'file folder-row', 'data-folder': top, style: `--i:${n++}` },
        folderIcon(),
        h('div', { class: 'fmeta' }, h('div', { class: 'fname', title: top }, top), h('div', { class: 'fsize' })),
        h('button', { class: 'x-btn', title: 'Remove folder', 'aria-label': `Remove folder ${top}`, html: ICON.x,
          onclick: () => removeItems((x) => topOf(x.path) === top, li, null, top) }));
      fileList.append(li);
      updateFolderRow(li, top);
    }
    refreshSummary();
  }
  function updateFolderRow(li, top) {
    const inside = state.files.filter((x) => topOf(x.path) === top);
    const size = inside.reduce((s, x) => s + x.file.size, 0);
    $('.fsize', li).textContent = inside.length ? `${inside.length} file${inside.length === 1 ? '' : 's'} · ${fmtBytes(size)}` : 'Empty folder';
  }
  function removeItems(match, li, thumb, top) {
    if (state.busy) return;
    state.files = state.files.filter((x) => !match(x));
    if (top) state.dirs = state.dirs.filter((d) => safeSegments(d)[0] !== top);
    li.classList.add('out');
    li.addEventListener('animationend', () => li.remove(), { once: true });
    if (thumb) URL.revokeObjectURL(thumb);
    refreshSummary();
  }
  function clearFiles() {
    state.files = [];
    state.dirs = [];
    $$('img', fileList).forEach((i) => URL.revokeObjectURL(i.src));
    fileList.textContent = '';
    $('#noteInput').value = '';
    refreshSummary();
  }

  $('#noteInput').addEventListener('input', refreshSummary);

  function payload() {
    const note = state.mode === 'note' ? $('#noteInput').value : '';
    const files = state.mode === 'files' ? state.files : [];
    const dirs = state.mode === 'files' ? state.dirs : [];
    return { files, dirs, note };
  }
  function refreshSummary() {
    const { files, dirs, note } = payload();
    drop.classList.toggle('compact', state.files.length + state.dirs.length > 0);
    const total = files.reduce((s, it) => s + it.file.size, 0);
    const ok = files.length > 0 || dirs.length > 0 || note.trim().length > 0;
    shareBtn.disabled = !ok || state.busy;
    let msg = 'Add a file or write a note to begin.';
    if (files.length) {
      const chunk = chooseChunk(total);
      const padded = Math.ceil(total / chunk) * chunk;
      const what = describe(groupItems(files, (it) => it.path, (it) => it.file.size));
      const count = files.length > 1 && /folder/.test(what) ? ` (${files.length} files)` : '';
      msg = `${what}${count} · ${fmtBytes(total)} — the host will only see ~${fmtBytes(padded || 0)} of noise`;
      if (padded > info.freeBytes) msg = `${what}${count} · ${fmtBytes(total)} — streams live from this tab, nothing stored on the host`;
    } else if (note.trim()) msg = `${note.length} characters — encrypted before sending`;
    $('#summary').textContent = msg;
  }

  function setProgress(btn, p, text) {
    btn.style.setProperty('--p', p);
    if (text) $('.cta-text', btn).textContent = text;
  }

  shareBtn.addEventListener('click', async () => {
    if (state.busy) return;
    if (typeof nacl === 'undefined') return toast('Encryption library failed to load', 'err');
    const { files, dirs, note } = payload();
    if (!files.length && !dirs.length && !note.trim()) return;
    state.busy = true;
    shareBtn.disabled = false;
    shareBtn.classList.add('busy');
    setProgress(shareBtn, 0, 'Generating key…');
    try {
      const share = await createShare(files, note, (p) => setProgress(shareBtn, p, `Encrypting & sending · ${Math.round(p * 100)}%`), { dirs: [...dirs] });
      mine.unshift(share);
      clearFiles();
      openLinkView(share);
    } catch (err) {
      toast(err.message || 'Upload failed', 'err');
    } finally {
      state.busy = false;
      shareBtn.classList.remove('busy');
      setProgress(shareBtn, 0, 'Encrypt & share');
      refreshSummary();
    }
  });

  async function createShare(files, note, onProgress, opts = {}) {
    await infoReady;
    const ttl = opts.ttl ?? state.ttl;
    const burn = opts.burn ?? state.burn;
    const key = nacl.randomBytes(32);
    const prefix = nacl.randomBytes(16);
    const items = asItems(files);
    files = items.map((it) => it.file);
    const entries = [];
    let total = 0;
    for (const it of items) {
      const f = it.file;
      entries.push({ name: f.name, path: it.path, type: f.type, size: f.size, offset: total, modified: f.lastModified });
      total += f.size;
    }
    // Big copies use 4 MiB blocks. Anything under 32 MiB stays at 1 MiB so small files aren't padded out.
    const chunk = chooseChunk(total);
    const chunks = Math.ceil(total / chunk) || 0;
    const bytes = chunks * (chunk + 40);
    const batchN = maxBatch(chunk + 40);

    // No size limit: if the host can't hold the share in RAM, stream it live from this tab instead.
    const fresh = opts.live ? info : await api('/api/info').then((r) => r.json()).catch(() => info);
    let live = !!opts.live || bytes > fresh.freeBytes;
    const open = (asLive) => api('/api/s', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ttl, burn, bytes, live: asLive, chunkSize: chunk }),
    });
    let res;
    try { res = await open(live); } catch (err) {
      if (err.status !== 507) throw err;
      live = true;
      res = await open(true);
    }
    const { id, ownerToken } = await res.json();
    const auth = { 'X-Owner-Token': ownerToken };

    // Read `count` chunks as one sequential slice (a 180 GB file should not be read 1 MiB at a time).
    // Disk reads are queued so parallel uploads don't turn a sequential file into random I/O.
    let readChain = Promise.resolve();
    const readSequential = (fn) => {
      const run = readChain.then(fn, fn);
      readChain = run.then(() => {}, () => {});
      return run;
    };
    async function readChunks(startIndex, count) {
      const bufs = Array.from({ length: count }, () => new Uint8Array(chunk));
      const start = startIndex * chunk;
      const end = Math.min(start + count * chunk, total);
      if (start >= end) return bufs;
      let lo = 0;
      let hi = entries.length;
      while (lo < hi) { const mid = (lo + hi) >> 1; if (entries[mid].offset + entries[mid].size <= start) lo = mid + 1; else hi = mid; }
      const jobs = [];
      for (let k = lo; k < entries.length && entries[k].offset < end; k++) {
        const e = entries[k];
        const a = Math.max(start, e.offset);
        const b = Math.min(end, e.offset + e.size);
        if (a < b) jobs.push(files[k].slice(a - e.offset, b - e.offset).arrayBuffer().then((ab) => ({ at: a - start, bytes: new Uint8Array(ab) })));
      }
      for (const part of await Promise.all(jobs)) {
        let pos = 0;
        while (pos < part.bytes.length) {
          const at = part.at + pos;
          const into = at % chunk;
          const n = Math.min(chunk - into, part.bytes.length - pos);
          bufs[Math.floor(at / chunk)].set(part.bytes.subarray(pos, pos + n), into);
          pos += n;
        }
      }
      return bufs;
    }
    async function sealChunks(start, count) {
      const plains = await readSequential(() => readChunks(start, count));
      return Promise.all(plains.map((plain, k) => blocks.seal(plain, start + k, key, prefix)));
    }

    let done = 0;
    onProgress(0);
    try {
      if (!live && chunks) await pool(Math.ceil(chunks / batchN), 4, async (b) => {
        const start = b * batchN;
        const count = Math.min(batchN, chunks - start);
        const parts = await sealChunks(start, count);
        await api(`/api/s/${id}/c/${start}?n=${count}`, { method: 'PUT', headers: auth, body: new Blob(parts) });
        done += count;
        onProgress(done / chunks);
      });

      const manifest = sealManifest({
        v: 1, cipher: blocks.cipher, prefix: b64u.enc(prefix), chunkSize: chunk, chunks, total, files: entries,
        note: note || undefined, burn, created: Date.now(), dirs: opts.dirs?.length ? opts.dirs : undefined,
      }, key);
      const sealed = await (await api(`/api/s/${id}/m`, { method: 'PUT', headers: { ...auth, 'X-Chunk-Count': String(chunks) }, body: manifest })).json();
      onProgress(1);

      const groups = groupItems(items, (it) => it.path, (it) => it.file.size);
      const first = groups[0] ? (groups[0].kind === 'folder' ? `${groups[0].name}/` : groups[0].items[0].file.name) : null;
      const label = first ? (groups.length === 1 ? first : `${first} + ${groups.length - 1} more`) : (opts.dirs?.length ? 'Empty folder' : 'Private note');
      const share = {
        id, ownerToken, key: b64u.enc(key), label, expiresAt: sealed.expiresAt, ttlMs: ttl * 60e3,
        burn, opens: 0, downloads: 0, gone: false, live, senderOnline: false, chunks, served: 0,
        chunk, plainTotal: total, pace: pace(),
      };
      share.onServe = () => { if (viewing === share) renderStatus(); };
      if (live) {
        // Don't hand out the link until this tab is ready to answer block requests.
        await Promise.race([new Promise((r) => { share.onReady = r; runLive(share, sealChunks); }), sleep(8000)]);
      }
      return share;
    } catch (err) {
      api(`/api/s/${id}`, { method: 'DELETE', headers: auth }).catch(() => {});
      throw err;
    }
  }

  // Live shares: keep a channel open to the host and answer block requests from this tab's files.
  // Several batches stay in flight so reading, encrypting and uploading overlap.
  async function runLive(share, sealChunks) {
    const auth = { 'X-Owner-Token': share.ownerToken };
    share.abort = new AbortController();
    let active = 0;
    const queue = [];
    const PARALLEL = 4;
    const pump = () => {
      while (active < PARALLEL && queue.length) {
        const [reqId, i, count] = queue.shift();
        active++;
        sealChunks(i, count)
          .then((parts) => fetch(`/api/s/${share.id}/c/${i}?r=${reqId}&n=${count}`, {
            method: 'PUT', headers: auth, body: new Blob(parts), cache: 'no-store',
            credentials: 'omit', referrerPolicy: 'no-referrer', signal: share.abort.signal,
          }))
          .then((r) => { if (r.ok) { share.served += count; share.onServe?.(); } })
          .catch(() => {})
          .finally(() => { active--; pump(); });
      }
    };
    while (!share.gone) {
      try {
        const res = await fetch(`/api/s/${share.id}/w`, { headers: auth, cache: 'no-store', signal: share.abort.signal });
        if (res.status === 404) { markGone(share, share.burn ? 'Received and self-destructed' : 'Expired — wiped from the host'); return; }
        if (!res.ok) throw new Error();
        const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
        let buf = '';
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += value;
          let nl;
          while ((nl = buf.indexOf('\n')) >= 0) {
            const line = buf.slice(0, nl);
            buf = buf.slice(nl + 1);
            if (line === 'ready') { share.senderOnline = true; share.onReady?.(); }
            const m = line.match(/^need (\S+) (\d+)(?: (\d+))?$/);
            if (m) { queue.push([m[1], +m[2], Math.max(1, +(m[3] || 1))]); pump(); }
          }
        }
      } catch { /* network blip or aborted */ }
      share.senderOnline = false;
      if (!share.gone) await new Promise((r) => setTimeout(r, 1500));
    }
  }

  // Closing the tab would end live shares — warn first.
  window.addEventListener('beforeunload', (e) => {
    if (mine.some((s) => s.live && !s.gone)) { e.preventDefault(); e.returnValue = ''; }
  });

  // ============================================================ LINK VIEW
  let viewing = null;
  let originIdx = 0;

  const linkFor = (s) => `${shareOrigins()[originIdx]?.origin || location.origin}/r/${s.id}#${s.key}`;

  function openLinkView(share) {
    viewing = share;
    const origins = shareOrigins();
    const sel = $('#originSel');
    sel.textContent = '';
    origins.forEach((o, i) => sel.append(h('option', { value: i }, `${o.origin.replace(/^https?:\/\//, '')}${o.name ? ` · ${o.name}` : ''}`)));
    sel.value = originIdx = Math.min(originIdx, origins.length - 1);
    $('#originRow').classList.toggle('hidden', origins.length < 2);
    renderLink();
    renderStatus();
    show('link');
  }
  function renderLink() {
    const url = linkFor(viewing);
    $('#linkOut').value = url;
    drawQR($('#qr'), url);
  }
  $('#originSel').addEventListener('change', (e) => { originIdx = +e.target.value; renderLink(); });

  $('#copyBtn').addEventListener('click', async () => {
    const btn = $('#copyBtn');
    const text = $('#linkOut').value;
    try { await navigator.clipboard.writeText(text); } catch {
      // navigator.clipboard is unavailable on plain-http LAN origins; fall back to selection copy.
      $('#linkOut').select();
      document.execCommand('copy');
      getSelection().removeAllRanges();
    }
    btn.classList.add('ok');
    btn.innerHTML = ICON.ok;
    toast('Link copied — it contains the key, share it carefully', 'ok');
    setTimeout(() => { btn.classList.remove('ok'); btn.innerHTML = '<svg viewBox="0 0 24 24"><rect x="8" y="8" width="12" height="12" rx="3"/><path d="M16 8V6a2 2 0 00-2-2H6a2 2 0 00-2 2v8a2 2 0 002 2h2"/></svg>'; }, 1600);
  });

  $('#revokeBtn').addEventListener('click', async () => {
    if (!viewing || viewing.gone) return show('send');
    await revoke(viewing);
    show('send');
  });
  $('#newBtn').addEventListener('click', () => show('send'));

  async function revoke(s) {
    try { await api(`/api/s/${s.id}`, { method: 'DELETE', headers: { 'X-Owner-Token': s.ownerToken } }); } catch { /* already gone */ }
    markGone(s, 'Revoked — wiped from the host');
    toast('Share revoked and wiped', 'ok');
  }

  function markGone(s, why) {
    if (s.gone) return;
    s.gone = why;
    s.key = '';
    s.abort?.abort();
    renderActive();
    if (s === viewing) renderStatus();
  }

  function renderStatus() {
    const s = viewing;
    if (!s) return;
    const ring = $('#ttlRing');
    const left = s.expiresAt - Date.now();
    const p = s.gone ? 0 : Math.max(0, Math.min(1, left / s.ttlMs));
    ring.style.setProperty('--p', p);
    ring.classList.toggle('low', p < 0.15);
    $('#ttlText').textContent = s.gone ? '—' : fmtLeft(left);
    const title = $('#statusTitle');
    const sub = $('#statusSub');
    if (s.gone) {
      title.textContent = 'Share destroyed';
      sub.textContent = s.gone;
      $('#revokeBtn').textContent = 'Back';
      $('.qr-wrap').style.filter = 'blur(12px) grayscale(1)';
      $('#linkOut').value = 'This link no longer works';
      return;
    }
    $('.qr-wrap').style.filter = '';
    $('#revokeBtn').textContent = 'Revoke now';
    if (s.downloads > 0) {
      title.textContent = `Received ${s.downloads > 1 ? `${s.downloads}×` : ''}`.trim();
      sub.textContent = 'The recipient has downloaded the files.';
    } else if (s.live && s.chunks && s.served > 0) {
      const p = Math.min(1, s.served / s.chunks);
      const sent = Math.min(s.plainTotal || 0, s.served * (s.chunk || CHUNK));
      const speed = s.pace ? s.pace(sent) : '';
      if (p >= 1) {
        title.textContent = 'Delivered';
        sub.textContent = 'The recipient has the data. Keep this tab open until their save finishes.';
      } else {
        title.textContent = `Sending · ${Math.round(p * 100)}%${speed ? ` · ${speed}` : ''}`;
        sub.textContent = 'Streaming live from this tab — keep it open until they’re done.';
      }
    } else if (s.opens > 0) {
      title.textContent = `Opened ${s.opens > 1 ? `${s.opens}×` : ''}`.trim();
      sub.textContent = 'Someone with the link unlocked the share.';
    } else {
      title.textContent = 'Waiting for recipient';
      sub.textContent = s.live
        ? 'Streaming live from this tab — keep it open until they’re done.'
        : s.burn ? 'Self-destructs after the first download.' : 'Nothing has been opened yet.';
    }
  }

  function renderActive() {
    const live = mine.filter((s) => !s.gone);
    $('#activeWrap').classList.toggle('hidden', live.length === 0);
    const ul = $('#activeList');
    const existing = new Map($$('.act', ul).map((li) => [li.dataset.id, li]));
    for (const [id, li] of existing) {
      if (!live.some((s) => s.id === id) && !li.classList.contains('out')) {
        li.classList.add('out');
        li.addEventListener('animationend', () => li.remove(), { once: true });
      }
    }
    live.forEach((s) => {
      let li = existing.get(s.id);
      if (!li) {
        li = h('li', { class: 'act', 'data-id': s.id },
          h('span', { class: 'act-dot' }),
          h('div', { class: 'act-main', onclick: () => openLinkView(s) }, h('b', {}, s.label), h('span', { class: 'act-meta' })),
          h('button', { class: 'x-btn', title: 'Revoke', 'aria-label': 'Revoke share', html: ICON.x, onclick: () => revoke(s) }));
        ul.prepend(li);
      }
      const bits = [`${fmtLeft(s.expiresAt - Date.now())} left`];
      if (s.live) {
        const p = s.chunks ? Math.min(1, s.served / s.chunks) : 0;
        bits.push(p > 0 && p < 1 ? `sending ${Math.round(p * 100)}%` : 'live · keep tab open');
      }
      if (s.burn) bits.push('self-destructs');
      if (s.opens) bits.push(`opened ${s.opens}×`);
      $('.act-meta', li).textContent = bits.join(' · ');
    });
  }

  // Poll our own shares for status (owner token required to see counters).
  setInterval(async () => {
    for (const s of mine) {
      if (s.gone) continue;
      if (s.expiresAt <= Date.now()) { markGone(s, 'Expired — wiped from the host'); continue; }
      try {
        const st = await (await api(`/api/s/${s.id}`, { headers: { 'X-Owner-Token': s.ownerToken } })).json();
        const changed = st.opens !== s.opens || st.downloads !== s.downloads;
        Object.assign(s, { opens: st.opens, downloads: st.downloads, expiresAt: st.expiresAt });
        if (changed && s === viewing && currentView?.id === 'view-link') {
          const row = $('.status-row');
          row.classList.remove('hit'); void row.offsetWidth; row.classList.add('hit');
        }
      } catch (err) {
        if (err.status === 404) markGone(s, s.burn ? 'Received and self-destructed' : 'Expired — wiped from the host');
      }
    }
    renderActive();
    if (currentView?.id === 'view-link') renderStatus();
  }, 2000);

  // ============================================================ QR
  function drawQR(canvas, text) {
    const qr = qrcode(0, 'M');
    qr.addData(text);
    qr.make();
    const n = qr.getModuleCount();
    const size = canvas.width;
    const cell = size / n;
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, size, size);
    const grad = ctx.createLinearGradient(0, 0, size, size);
    grad.addColorStop(0, '#4c1d95');
    grad.addColorStop(0.5, '#3730a3');
    grad.addColorStop(1, '#0e7490');
    ctx.fillStyle = grad;
    const isFinder = (r, c) => (r < 7 && c < 7) || (r < 7 && c >= n - 7) || (r >= n - 7 && c < 7);
    const rr = (x, y, w, hgt, rad) => { ctx.beginPath(); ctx.roundRect(x, y, w, hgt, rad); ctx.fill(); };
    for (let r = 0; r < n; r++) {
      for (let c = 0; c < n; c++) {
        if (!qr.isDark(r, c) || isFinder(r, c)) continue;
        const pad = cell * 0.1;
        rr(c * cell + pad, r * cell + pad, cell - 2 * pad, cell - 2 * pad, cell * 0.38);
      }
    }
    for (const [r, c] of [[0, 0], [0, n - 7], [n - 7, 0]]) {
      const x = c * cell; const y = r * cell;
      rr(x, y, 7 * cell, 7 * cell, cell * 2.2);
      ctx.fillStyle = '#fff';
      rr(x + cell, y + cell, 5 * cell, 5 * cell, cell * 1.5);
      ctx.fillStyle = grad;
      rr(x + 2 * cell, y + 2 * cell, 3 * cell, 3 * cell, cell);
    }
  }

  // Writing real folders needs the File System Access API (Chromium on HTTPS or localhost).
  const canSaveFolders = typeof window.showDirectoryPicker === 'function';
  // Beyond this, saving without streaming to disk relies on the browser buffering everything.
  const HUGE = 4 * 1024 ** 3;
  const hugeWarning = (bytes) => `This is ${fmtBytes(bytes)}. To save something this big reliably, open LocShare over HTTPS (npm run https) in Chrome or Edge — it then streams straight to disk.`;

  // ============================================================ save location
  // Where received files go. Where the browser allows it, the person picks a folder once; it's
  // remembered on this device (a local folder handle in IndexedDB — never sent anywhere) and
  // every save goes straight into it. Elsewhere the browser decides, so we explain the options.
  const saveDest = { handle: null, granted: false };
  const kv = {
    db: null,
    open() {
      this.db ||= new Promise((res, rej) => {
        const r = indexedDB.open('locshare', 1);
        r.onupgradeneeded = () => r.result.createObjectStore('kv');
        r.onsuccess = () => res(r.result);
        r.onerror = () => rej(r.error);
      });
      return this.db;
    },
    async get(k) {
      const db = await this.open();
      return new Promise((res, rej) => { const q = db.transaction('kv').objectStore('kv').get(k); q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error); });
    },
    async set(k, v) {
      const db = await this.open();
      return new Promise((res, rej) => {
        const t = db.transaction('kv', 'readwrite');
        if (v === undefined) t.objectStore('kv').delete(k); else t.objectStore('kv').put(v, k);
        t.oncomplete = () => res();
        t.onerror = () => rej(t.error);
      });
    },
  };

  async function loadSaveDest() {
    if (canSaveFolders) {
      try { saveDest.handle = (await kv.get('saveDir')) || null; } catch { saveDest.handle = null; }
      if (saveDest.handle) {
        try { saveDest.granted = (await saveDest.handle.queryPermission({ mode: 'readwrite' })) === 'granted'; } catch { saveDest.handle = null; }
      }
    }
    renderSaveLoc();
  }

  // The chosen folder, if we may write to it. `interactive` may show the browser's "allow" prompt,
  // which needs a click — so pass true only from click handlers.
  async function destDir(interactive) {
    const hdl = saveDest.handle;
    if (!hdl) return null;
    let perm = await hdl.queryPermission({ mode: 'readwrite' }).catch(() => 'denied');
    if (perm !== 'granted' && interactive) perm = await hdl.requestPermission({ mode: 'readwrite' }).catch(() => 'denied');
    const was = saveDest.granted;
    saveDest.granted = perm === 'granted';
    if (was !== saveDest.granted) renderSaveLoc();
    return saveDest.granted ? hdl : null;
  }

  async function chooseSaveDest() {
    try {
      const hdl = await window.showDirectoryPicker({ id: 'locshare-dest', mode: 'readwrite' });
      saveDest.handle = hdl;
      saveDest.granted = true;
      try { await kv.set('saveDir', hdl); } catch { /* not remembered, still used this visit */ }
      renderSaveLoc();
      toast(`Received files will go to “${hdl.name}”`, 'ok');
    } catch (err) {
      if (err.name !== 'AbortError') toast(err.message, 'err');
    }
  }

  async function clearSaveDest() {
    saveDest.handle = null;
    saveDest.granted = false;
    try { await kv.set('saveDir', undefined); } catch { /* ignore */ }
    renderSaveLoc();
    toast('Will ask where to save each time');
  }

  const isChromium = /Chrome\/|Edg\//.test(navigator.userAgent) && !/OPR\//.test(navigator.userAgent);
  const FOLDER_SVG = '<svg viewBox="0 0 24 24"><path d="M3 7.5A2.5 2.5 0 015.5 5h3.6l2 2.2h7.4A2.5 2.5 0 0121 9.7v7.8A2.5 2.5 0 0118.5 20h-13A2.5 2.5 0 013 17.5z"/></svg>';
  const saveLabels = new Set(); // buttons whose label mentions the destination

  function renderSaveLoc() {
    for (const el of $$('.save-loc')) {
      el.textContent = '';
      el.classList.toggle('set', !!saveDest.handle);
      const text = h('span', { class: 'sl-text' }, h('small', {}, 'Save to'));
      const actions = h('span', { class: 'sl-actions' });
      if (!canSaveFolders) {
        text.append(h('b', {}, 'Your browser’s download folder'));
        actions.append(h('button', { class: 'ghost small', type: 'button', 'aria-expanded': 'false', onclick: (e) => {
          const open = el.classList.toggle('help-open');
          e.currentTarget.setAttribute('aria-expanded', open);
        } }, 'Change…'));
        const tips = [];
        if (isChromium) {
          tips.push(h('li', { html: 'Easiest: start LocShare with <code>npm run https</code> and open the <b>https://</b> address. You can then pick any folder here once, and everything lands there.' }));
        } else {
          tips.push(h('li', { html: 'Picking a folder from the page works in <b>Chrome</b> and <b>Edge</b> (with <code>npm run https</code>).' }));
        }
        tips.push(h('li', { html: 'Or make your browser ask every time: <b>Chrome/Edge</b> → Settings → Downloads → “Ask where to save each file” · <b>Firefox</b> → Settings → Downloads → “Always ask you where to save files” · <b>Safari</b> → Settings → General → File download location → “Ask for each download”.' }));
        el.append(h('span', { class: 'sl-ico', html: FOLDER_SVG }), text, actions,
          h('div', { class: 'sl-help' }, h('p', {}, 'Browsers only let web pages save into a chosen folder over a secure (HTTPS) connection.'), h('ul', {}, tips)));
      } else if (!saveDest.handle) {
        text.append(h('b', {}, 'Ask each time'));
        actions.append(h('button', { class: 'ghost small', type: 'button', onclick: chooseSaveDest }, 'Choose folder'));
        el.append(h('span', { class: 'sl-ico', html: FOLDER_SVG }), text, actions);
      } else {
        text.append(h('b', { title: saveDest.handle.name }, saveDest.handle.name));
        if (!saveDest.granted) text.append(h('em', {}, 'Your browser will ask to allow access when you save'));
        actions.append(
          h('button', { class: 'ghost small', type: 'button', onclick: chooseSaveDest }, 'Change'),
          h('button', { class: 'x-btn', type: 'button', title: 'Ask each time instead', 'aria-label': 'Stop using this folder', html: ICON.x, onclick: clearSaveDest }));
        el.append(h('span', { class: 'sl-ico', html: FOLDER_SVG }), text, actions);
      }
    }
    for (const fn of saveLabels) fn();
  }

  // ============================================================ share reader
  // Shared by the one-off receive page and live sessions: decrypts a share's files on demand.

  async function fetchManifest(id, key) {
    const bytes = new Uint8Array(await (await api(`/api/s/${id}/m`)).arrayBuffer());
    return openManifest(bytes, key);
  }

  function makeReader(id, key, manifest) {
    const prefix = b64u.dec(manifest.prefix);
    const C = manifest.chunkSize;
    const cipher = manifest.cipher === 'aes-256-gcm' ? 'aes-256-gcm' : 'xsalsa20poly1305';
    const files = manifest.files;
    const total = files.reduce((s, f) => s + f.size, 0);
    const kept = new Map(); // idx -> { blob, crc }: decrypted copies held in memory
    const batchN = maxBatch(C + 40);

    // Pull `count` ciphertext blocks in one response and decrypt each as it arrives.
    async function fetchRange(start, count) {
      if (cipher === 'aes-256-gcm' && !(globalThis.crypto && crypto.subtle)) {
        throw Object.assign(new Error('This transfer uses AES-GCM. Open the https:// address of this LocShare to receive it.'), { fatal: true });
      }
      const size = C + 40;
      for (let attempt = 0; ; attempt++) {
        try {
          const res = await api(`/api/s/${id}/c/${start}?n=${count}`);
          const reader = res.body.getReader();
          const openings = new Array(count);
          let frame = new Uint8Array(size);
          let filled = 0;
          let got = 0;
          for (;;) {
            const { value, done } = await reader.read();
            if (value) {
              let off = 0;
              while (off < value.length) {
                const n = Math.min(size - filled, value.length - off);
                frame.set(value.subarray(off, off + n), filled);
                filled += n;
                off += n;
                if (filled === size) {
                  if (got >= count) throw Object.assign(new Error('Unexpected extra data'), { fatal: true });
                  openings[got] = blocks.open(frame, start + got, key, prefix, cipher);
                  got++;
                  frame = new Uint8Array(size);
                  filled = 0;
                }
              }
            }
            if (done) break;
          }
          if (got !== count || filled !== 0) throw new Error('Incomplete block');
          return await Promise.all(openings);
        } catch (err) {
          // A live sender can blip (tab reconnecting, phone busy): retry briefly before giving up.
          if (err.fatal || err.status === 404 || err.status === 410 || err.status === 400 || attempt >= 4) throw err;
          await sleep(400 * (attempt + 1));
        }
      }
    }

    // Decrypt one file in order, with several batches fetched ahead of the disk write.
    // Plaintext is handed to `write` in ~8 MiB pieces and can be dropped right after.
    async function streamFile(idx, write, onProgress, wantCrc) {
      const f = files[idx];
      if (kept.has(idx)) { const k = kept.get(idx); await write(k.blob); onProgress?.(1); return k.crc; }
      if (f.size === 0) { onProgress?.(1); return 0; }
      const first = Math.floor(f.offset / C);
      const n = Math.floor((f.offset + f.size - 1) / C) - first + 1;
      const PARALLEL = 4;
      const inflight = new Map();
      let scheduled = 0;
      const launch = () => {
        while (inflight.size < PARALLEL && scheduled < n) {
          const k = scheduled;
          const count = Math.min(batchN, n - k);
          scheduled += count;
          const pr = fetchRange(first + k, count);
          pr.catch(() => {});
          inflight.set(k, { count, pr });
        }
      };
      launch();
      let crc = 0;
      const WRITE = 8 * 1024 * 1024;
      let bin = [];
      let binSize = 0;
      const flush = async () => {
        if (!binSize) return;
        const payload = bin.length === 1 ? bin[0] : new Blob(bin);
        bin = [];
        binSize = 0;
        await write(payload);
      };
      let doneChunks = 0;
      for (let k = 0; k < n;) {
        const job = inflight.get(k);
        inflight.delete(k);
        const plains = await job.pr;
        launch();
        for (let j = 0; j < job.count; j++, k++) {
          const plain = plains[j];
          const i = first + k;
          let part = plain.subarray(Math.max(f.offset, i * C) - i * C, Math.min(f.offset + f.size, (i + 1) * C) - i * C);
          if (wantCrc) crc = crc32(part, crc);
          // A view into a larger block must be copied. Some writers ignore byteOffset and would
          // append the padding that hides the real file size.
          if (part.byteLength && (part.byteOffset !== 0 || part.byteLength !== part.buffer.byteLength)) part = part.slice();
          if (part.length) { bin.push(part); binSize += part.length; }
          if (binSize >= WRITE) await flush();
          doneChunks++;
          onProgress?.(doneChunks / n);
        }
      }
      await flush();
      return crc;
    }

    // Decrypt into memory (for previews and instant saves).
    async function keep(idx, onProgress) {
      if (kept.has(idx)) { onProgress?.(1); return kept.get(idx); }
      const parts = [];
      const crc = await streamFile(idx, (d) => { parts.push(d); }, onProgress, true);
      const r = { blob: new Blob(parts, { type: files[idx].type || 'application/octet-stream' }), crc };
      kept.set(idx, r);
      return r;
    }

    // NB: these must be called straight from a click handler — save dialogs need the user gesture.
    async function saveFile(idx, onProgress) {
      const f = files[idx];
      const name = safeSegments(f.path || f.name).pop() || 'file';
      const dest = await destDir(true);
      if (dest) return saveTree([idx], [], (frac, i, p) => onProgress?.(p), dest, true);
      if (kept.has(idx)) { saveBlob(kept.get(idx).blob, name); onProgress?.(1); return; }
      const sink = await openSink(name, f.type);
      try { await streamFile(idx, (d) => sink.write(d), onProgress); await sink.close(); } catch (e) { sink.abort(); throw e; }
    }

    const dirs = (manifest.dirs || []).map(String);
    const pathOf = (idx) => files[idx].path || files[idx].name;

    // Write files into a real folder on disk, recreating the directory tree (Chromium, HTTPS/localhost).
    // `root` is the remembered save folder, or the person picks one now. `flat` drops folder paths.
    async function saveTree(idxs, dirList, onProgress, root, flat) {
      root ||= await window.showDirectoryPicker({ id: 'locshare', mode: 'readwrite' });
      const exists = async (name) => {
        for (const get of ['getDirectoryHandle', 'getFileHandle']) {
          try { await root[get](name); return true; } catch { /* not this kind */ }
        }
        return false;
      };
      // Never overwrite: a top-level name that already exists becomes "Name (2)".
      const renamed = new Map();
      const topName = async (name) => {
        if (renamed.has(name)) return renamed.get(name);
        let out = name;
        for (let i = 2; await exists(out); i++) out = name.replace(/(\.[^.]*)?$/, ` (${i})$1`);
        renamed.set(name, out);
        return out;
      };
      const dirCache = new Map([['', root]]);
      const dirFor = async (segs) => {
        let key = '';
        let handle = root;
        for (const seg of segs) {
          key += '/' + seg;
          if (!dirCache.has(key)) dirCache.set(key, await handle.getDirectoryHandle(seg, { create: true }));
          handle = dirCache.get(key);
        }
        return handle;
      };
      const mapPath = async (path) => {
        const segs = safeSegments(path);
        if (segs.length) segs[0] = await topName(segs[0]);
        return segs;
      };
      for (const d of dirList) { const segs = await mapPath(d); if (segs.length) await dirFor(segs); }
      const totalBytes = idxs.reduce((n, i) => n + files[i].size, 0);
      let doneBytes = 0;
      for (const idx of idxs) {
        const segs = await mapPath(flat ? safeSegments(pathOf(idx)).pop() || 'file' : pathOf(idx));
        const name = segs.pop() || 'file';
        const dir = await dirFor(segs);
        const w = await (await dir.getFileHandle(name, { create: true })).createWritable();
        const size = files[idx].size;
        try {
          await streamFile(idx, (d) => w.write(d), (p) => onProgress?.(totalBytes ? (doneBytes + p * size) / totalBytes : 1, idx, p));
          await w.close();
        } catch (e) { await w.abort().catch(() => {}); throw e; }
        doneBytes += size;
      }
    }

    // Fallback where browsers can't write folders: one zip that keeps the folder structure.
    async function saveZip(idxs, dirList, zipName, onProgress) {
      const sink = await openSink(zipName, 'application/zip');
      try {
        const zip = zipWriter(sink);
        const totalBytes = idxs.reduce((n, i) => n + files[i].size, 0);
        let doneBytes = 0;
        for (const d of dirList) await zip.add(d + '/', 0, async () => 0);
        for (const idx of idxs) {
          const size = files[idx].size;
          await zip.add(pathOf(idx), size, (write) => streamFile(idx, write, (p) => onProgress?.(totalBytes ? (doneBytes + p * size) / totalBytes : 1, idx, p), true));
          doneBytes += size;
        }
        await zip.finish();
      } catch (e) { sink.abort(); throw e; }
    }

    const all = files.map((_, i) => i);
    const today = () => new Date().toISOString().slice(0, 10);

    async function saveFolder(top, onProgress) {
      const idxs = all.filter((i) => topOf(pathOf(i)) === top);
      const sub = dirs.filter((d) => safeSegments(d)[0] === top);
      const dest = await destDir(true);
      if (dest || canSaveFolders) return saveTree(idxs, sub, onProgress, dest);
      return saveZip(idxs, sub, `${top}.zip`, onProgress);
    }

    async function saveAll(onProgress) {
      if (files.length === 1 && !dirs.length) return saveFile(0, (p) => onProgress?.(p, 0, p));
      const dest = await destDir(true);
      if (dest || canSaveFolders) return saveTree(all, dirs, onProgress, dest);
      return saveZip(all, dirs, `locshare-${today()}.zip`, onProgress);
    }

    const hasFolders = all.some((i) => topOf(pathOf(i))) || dirs.length > 0;
    return { id, manifest, files, total, dirs, hasFolders, kept, keep, saveFile, saveFolder, saveAll, ack: () => api(`/api/s/${id}/a`, { method: 'POST' }).catch(() => {}) };
  }

  // One file row with a progress bar and a save button.
  function fileRow(reader, idx, opts = {}) {
    const f = reader.files[idx];
    const bar = h('div', { class: 'fbar' }, h('i'));
    bar.style.display = 'none';
    const icon = fileIcon(f.name, f.type);
    const label = opts.label || f.name;
    const btn = opts.button === false ? null : h('button', { class: 'dl-btn', title: 'Save', 'aria-label': `Save ${label}`, html: ICON.dl });
    const sizeEl = h('div', { class: 'fsize' }, fmtBytes(f.size));
    const li = h('li', { class: 'file', style: `--i:${opts.i ?? idx}` },
      icon,
      h('div', { class: 'fmeta' }, h('div', { class: 'fname', title: label }, label), sizeEl, bar),
      btn);
    const rate = pace();
    const progress = (p) => {
      bar.style.display = '';
      bar.style.setProperty('--p', p);
      if (f.size >= 8 * 1024 * 1024 && p > 0) {
        const speed = rate(p * f.size);
        sizeEl.textContent = `${Math.round(p * 100)}%${speed ? ` · ${speed}` : ''} · ${fmtBytes(f.size)}`;
      }
    };
    const thumb = () => {
      if (kindOf(f.name, f.type).k === 'img' && f.size <= 6e6 && !/svg/.test(f.type)) {
        reader.keep(idx).then(({ blob }) => setThumb(icon, URL.createObjectURL(blob))).catch(() => {});
      }
    };
    if (btn) {
      btn.addEventListener('click', async () => {
        if (btn.disabled) return;
        btn.disabled = true;
        try {
          const pending = reader.saveFile(idx, progress); // opens the save dialog synchronously
          btn.innerHTML = ICON.spin;
          await pending;
          reader.ack();
          btn.classList.add('done');
          btn.innerHTML = ICON.ok;
          if (savedWhere()) toast(`Saved “${label}”${savedWhere()}`, 'ok');
        } catch (err) {
          if (err.name !== 'AbortError') toast(err.message, 'err');
          btn.innerHTML = ICON.dl;
        } finally { btn.disabled = false; }
      });
    }
    if (opts.preview !== false) thumb();
    return { li, progress, icon, btn, thumb };
  }

  // Render a share's contents: top-level folders collapse into one expandable row each.
  function renderShare(reader, ul, opts = {}) {
    const rowsByIdx = new Map();
    const folderRows = [];
    const groups = groupItems(reader.files, (f) => f.path || f.name, (f) => f.size);
    // Empty top-level folders still deserve a row.
    for (const d of reader.dirs) {
      const top = safeSegments(d)[0];
      if (top && !groups.some((g) => g.kind === 'folder' && g.name === top)) groups.push({ kind: 'folder', name: top, items: [], idx: [], size: 0 });
    }
    groups.forEach((g, gi) => {
      if (g.kind === 'file') {
        const row = fileRow(reader, g.idx[0], { ...opts, i: gi });
        rowsByIdx.set(g.idx[0], row);
        ul.append(row.li);
        return;
      }
      const bar = h('div', { class: 'fbar' }, h('i'));
      bar.style.display = 'none';
      const sub = h('ul', { class: 'files sub' });
      const toggle = h('button', { class: 'chev-btn', title: 'Show contents', 'aria-expanded': 'false', html: ICON.chev });
      const btn = opts.button === false ? null : h('button', { class: 'dl-btn', title: canSaveFolders ? 'Save folder' : 'Save folder (.zip)', 'aria-label': `Save folder ${g.name}`, html: ICON.folderDl });
      const li = h('li', { class: 'file folder-row', style: `--i:${gi}` },
        folderIcon(),
        h('div', { class: 'fmeta' },
          h('div', { class: 'fname', title: g.name }, g.name),
          h('div', { class: 'fsize' }, `${g.idx.length} file${g.idx.length === 1 ? '' : 's'} · ${fmtBytes(g.size)}`),
          bar),
        h('div', { class: 'row-btns' }, toggle, btn));
      const wrap = h('li', { class: 'folder' }, li, sub);
      let built = false;
      toggle.addEventListener('click', () => {
        const open = wrap.classList.toggle('open');
        toggle.setAttribute('aria-expanded', open);
        if (open && !built) { // build children lazily — folders can hold thousands of files
          built = true;
          g.idx.slice(0, 500).forEach((idx, k) => {
            const label = safeSegments(reader.files[idx].path).slice(1).join('/');
            const row = fileRow(reader, idx, { ...opts, label, i: Math.min(k, 12), preview: opts.preview });
            rowsByIdx.set(idx, row);
            sub.append(row.li);
          });
          if (g.idx.length > 500) sub.append(h('li', { class: 'more' }, `…and ${g.idx.length - 500} more — save the folder to get everything`));
        }
      });
      const done = new Map();
      let sum = 0;
      const progress = (idx, p) => {
        const now = p * reader.files[idx].size;
        sum += now - (done.get(idx) || 0);
        done.set(idx, now);
        bar.style.display = '';
        bar.style.setProperty('--p', g.size ? Math.min(1, sum / g.size) : 1);
      };
      g.idx.forEach((idx) => folderRows[idx] = progress);
      if (btn) {
        btn.addEventListener('click', async () => {
          if (btn.disabled) return;
          btn.disabled = true;
          try {
            const pending = reader.saveFolder(g.name, (frac, idx, p) => { progress(idx, p); rowsByIdx.get(idx)?.progress(p); });
            btn.innerHTML = ICON.spin;
            await pending;
            bar.style.display = ''; bar.style.setProperty('--p', 1);
            reader.ack();
            btn.classList.add('done');
            btn.innerHTML = ICON.ok;
            toast(savedWhere() ? `Saved folder “${g.name}”${savedWhere()}`
              : canSaveFolders ? `Saved folder “${g.name}”` : `Saved “${g.name}.zip” — this browser can’t write folders directly`, 'ok');
          } catch (err) {
            if (err.name !== 'AbortError') toast(err.message, 'err');
            btn.innerHTML = ICON.folderDl;
          } finally { btn.disabled = false; }
        });
      }
      ul.append(wrap);
    });
    return {
      groups,
      progress(idx, p) { rowsByIdx.get(idx)?.progress(p); folderRows[idx]?.(idx, p); },
      thumbs() { for (const row of rowsByIdx.values()) row.thumb(); },
    };
  }

  const destName = () => (saveDest.handle ? `“${saveDest.handle.name}”` : null);
  const saveAllLabel = (reader) => {
    const single = reader.files.length === 1 && !reader.hasFolders;
    if (destName()) return `${single ? 'Save' : 'Save all'} to ${destName()}`;
    if (single) return 'Save';
    return canSaveFolders ? (reader.hasFolders ? 'Save all to a folder' : 'Save all into a folder') : 'Save all as .zip';
  };
  const savedWhere = () => (destName() && saveDest.granted ? ` to ${destName()}` : '');

  async function copyText(text, el) {
    try { await navigator.clipboard.writeText(text); } catch {
      // navigator.clipboard is unavailable on plain-http LAN origins; fall back to a selection copy.
      const r = document.createRange();
      r.selectNodeContents(el);
      getSelection().removeAllRanges(); getSelection().addRange(r);
      document.execCommand('copy');
      getSelection().removeAllRanges();
    }
  }

  // ============================================================ RECEIVE (one-off link)
  async function receive(id) {
    show('recv');
    const lock = $('#lockAnim');
    const title = $('#recvTitle');
    const sub = $('#recvSub');
    lock.className = 'lock working';

    // The key arrives in the #fragment. Move it into tab-scoped memory and scrub it from
    // the address bar so it never lingers in browser history.
    let keyStr = location.hash.slice(1);
    if (keyStr) {
      try { sessionStorage.setItem(`k:${id}`, keyStr); } catch { /* private mode */ }
      history.replaceState(null, '', location.pathname);
    } else {
      try { keyStr = sessionStorage.getItem(`k:${id}`) || ''; } catch { /* ignore */ }
    }
    const forget = () => { try { sessionStorage.removeItem(`k:${id}`); } catch { /* ignore */ } };

    const failWith = (t, s) => {
      lock.className = 'lock bad';
      title.textContent = t;
      sub.textContent = s;
      $('#recvMeta').textContent = '';
    };

    let key;
    try { key = b64u.dec(keyStr); } catch { key = null; }
    if (!key || key.length !== 32) return failWith('Key missing', 'This link is incomplete — the part after “#” holds the decryption key. Ask the sender to share it again.');

    let manifest;
    try {
      if (typeof nacl === 'undefined') throw new Error('Encryption library failed to load');
      manifest = await fetchManifest(id, key);
    } catch (err) {
      forget();
      return failWith('Nothing here', err.status === 404 ? 'This share has expired, been revoked, or already self-destructed.' : err.message);
    }
    if (!manifest) return failWith('Wrong key', 'The link’s key doesn’t match this share. Nothing could be decrypted.');

    const reader = makeReader(id, key, manifest);
    await sleep(450); // let the unlock animation breathe
    lock.className = 'lock open';

    const fileCount = manifest.files.length;
    const summary = describe(groupItems(manifest.files, (f) => f.path || f.name, (f) => f.size));
    title.textContent = fileCount ? `${summary[0].toUpperCase()}${summary.slice(1)} for you` : 'A private note for you';
    sub.textContent = manifest.burn
      ? 'This share self-destructs once saved. Make sure you’re ready.'
      : 'Decrypted locally in this browser. The host never saw any of it.';

    if (manifest.note) {
      $('#noteText').textContent = manifest.note;
      $('#noteOut').classList.remove('hidden');
      $('#noteCopy').onclick = async () => { await copyText(manifest.note, $('#noteText')); toast('Note copied', 'ok'); };
    }

    // Self-destructing shares get no per-file buttons or previews: one save, then gone.
    const view = renderShare(reader, $('#recvList'), { button: !manifest.burn, preview: !manifest.burn });

    $('#recvMeta').textContent = `${fileCount ? `${fmtBytes(reader.total)} · ` : ''}verified & decrypted on this device`;
    $('#recvSaveLoc').classList.toggle('hidden', !fileCount);
    if (reader.total > HUGE && !canSaveFolders) toast(hugeWarning(reader.total), 'err');

    // Note-only self-destructing share: burn right away, the note is already on screen.
    if (manifest.burn && !fileCount) {
      api(`/api/s/${id}`, { method: 'DELETE' }).catch(() => {});
      forget();
      sub.textContent = 'This note has been wiped from the host. Copy it now — it won’t be shown again.';
      return;
    }

    const saveAll = $('#saveAllBtn');
    if (fileCount > 1 || reader.hasFolders || manifest.burn) {
      saveAll.classList.remove('hidden');
      const relabel = () => {
        if (saveAll.classList.contains('busy') || saveAll.disabled) return;
        const l = saveAllLabel(reader);
        $('.cta-text', saveAll).textContent = manifest.burn ? `Decrypt & ${l[0].toLowerCase()}${l.slice(1)}` : l;
      };
      relabel();
      saveLabels.add(relabel);
      const rate = pace();
      saveAll.onclick = async () => {
        if (saveAll.classList.contains('busy') || saveAll.disabled) return;
        try {
          const pending = reader.saveAll((frac, idx, p) => {
            view.progress(idx, p);
            const speed = rate(frac * reader.total);
            setProgress(saveAll, frac, `Saving · ${Math.round(frac * 100)}%${speed ? ` · ${speed}` : ''}`);
          });
          saveAll.classList.add('busy');
          await pending;
          setProgress(saveAll, 1, 'Saved');
          toast(`Saved ${fileCount > 1 ? summary : manifest.files[0].name}${savedWhere()}`, 'ok');
          if (manifest.burn) {
            await api(`/api/s/${id}`, { method: 'DELETE' }).catch(() => {});
            forget();
            reader.kept.clear();
            sub.textContent = 'Saved. The share has self-destructed and was wiped from the host.';
            saveAll.disabled = true;
            setProgress(saveAll, 1, 'Destroyed ✓');
          } else reader.ack();
        } catch (err) {
          if (err.name === 'AbortError') return;
          toast(err.message, 'err');
          setProgress(saveAll, 0, 'Try again');
        } finally {
          saveAll.classList.remove('busy');
        }
      };
    }
  }

  // ============================================================ LIVE SESSION (paired devices)
  // Devices that open the same session link form a tiny encrypted room. Messages (device names,
  // texts, file offers) are sealed with the room key; files travel as live shares that the other
  // side starts pulling the moment they're offered — no upload step, no size limit.
  const AUTO_RECEIVE = 256 * 1024 * 1024; // smaller batches are decrypted automatically on arrival
  const room = { id: null, key: null, me: null, token: null, peers: new Map(), shares: [], abort: null, closed: true, inviteOpen: false };

  function deviceInfo() {
    const ua = navigator.userAgent;
    const os = /iPhone/.test(ua) ? 'iPhone' : /iPad/.test(ua) ? 'iPad'
      : /Android/.test(ua) ? (/Mobile/.test(ua) ? 'Android phone' : 'Android tablet')
      : /CrOS/.test(ua) ? 'Chromebook' : /Mac/.test(ua) ? (navigator.maxTouchPoints > 1 ? 'iPad' : 'Mac')
      : /Windows/.test(ua) ? 'Windows PC' : /Linux/.test(ua) ? 'Linux' : 'Device';
    const br = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : '';
    const kind = /iPhone|Android phone/.test(os) ? 'phone' : /iPad|tablet/.test(os) ? 'tablet' : 'desktop';
    return { name: br ? `${os} · ${br}` : os, kind };
  }
  const myDevice = deviceInfo();
  const hueOf = (id) => [...id].reduce((a, c) => (a * 31 + c.charCodeAt(0)) % 360, 17);
  const rid = () => b64u.enc(nacl.randomBytes(9));
  const roomLink = () => `${shareOrigins()[originIdx]?.origin || location.origin}/p/${room.id}#${b64u.enc(room.key)}`;

  function sealMsg(obj) {
    const json = new TextEncoder().encode(JSON.stringify(obj));
    const padded = new Uint8Array(Math.ceil((json.length + 4) / 256) * 256); // blur message lengths
    new DataView(padded.buffer).setUint32(0, json.length);
    padded.set(json, 4);
    return b64u.enc(seal(padded, nacl.randomBytes(NONCE), room.key));
  }
  function openMsg(str) {
    try { return openManifest(b64u.dec(str), room.key); } catch { return null; }
  }

  async function roomSend(obj, to) {
    if (!room.me) throw new Error('Not connected yet — reconnecting…');
    await api(`/api/r/${room.id}/send${to ? `?to=${to}` : ''}`, {
      method: 'POST',
      headers: { 'X-Peer': room.me, 'X-Peer-Token': room.token, 'Content-Type': 'text/plain' },
      body: sealMsg(obj),
    });
  }

  async function readLines(res, onLine) {
    const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
    let buf = '';
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return;
      buf += value;
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (line && line[0] !== ':') onLine(line);
      }
    }
  }

  async function startRoom() {
    if (typeof nacl === 'undefined') return toast('Encryption library failed to load', 'err');
    try {
      await infoReady;
      const { id } = await (await api('/api/r', { method: 'POST' })).json();
      enterRoom(id, nacl.randomBytes(32));
    } catch (err) { toast(err.message, 'err'); }
  }

  async function enterRoom(id, key) {
    Object.assign(room, { id, key, me: null, token: null, closed: false, inviteOpen: false });
    room.peers.clear();
    $('#feed').textContent = '';
    // Keep the key in tab memory only and scrub it from the address bar / history.
    try { sessionStorage.setItem(`p:${id}`, b64u.enc(key)); } catch { /* private mode */ }
    history.replaceState(null, '', `/p/${id}`);
    show('room');
    renderInvite();
    renderRoom();
    room.abort = new AbortController();
    let failures = 0;
    while (!room.closed && room.id === id) {
      try {
        const res = await fetch(`/api/r/${id}/events`, { cache: 'no-store', signal: room.abort.signal });
        if (res.status === 404) return endRoom('This session has ended.');
        if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Connection failed');
        failures = 0;
        await readLines(res, onRoomLine);
      } catch (err) {
        if (room.closed) return;
        if (++failures === 3) toast(err.message || 'Connection lost — retrying', 'err');
      }
      room.me = null;
      room.peers.clear();
      renderRoom();
      if (!room.closed) await sleep(1200);
    }
  }

  function onRoomLine(line) {
    const [cmd, a, b] = line.split(' ');
    if (cmd === 'hi') {
      room.me = a;
      room.token = b;
      renderRoom();
      roomSend({ t: 'hello', ...myDevice }).catch(() => {});
    } else if (cmd === 'join') {
      roomSend({ t: 'hello', ...myDevice }, a).catch(() => {});
    } else if (cmd === 'leave') {
      const p = room.peers.get(a);
      if (p) { room.peers.delete(a); toast(`${p.name} disconnected`); renderRoom(); }
    } else if (cmd === 'msg') {
      const msg = openMsg(b);
      if (msg) onRoomMsg(a, msg); // anything that doesn't decrypt with the room key is ignored
    } else if (cmd === 'closed') {
      endRoom('This session has ended.');
    }
  }

  function onRoomMsg(from, msg) {
    if (msg.t === 'hello') {
      const isNew = !room.peers.has(from);
      room.peers.set(from, { name: String(msg.name || 'Device').slice(0, 60), kind: msg.kind });
      if (isNew) {
        toast(`${room.peers.get(from).name} connected`, 'ok');
        room.inviteOpen = false;
        renderRoom();
      }
      return;
    }
    const peer = room.peers.get(from);
    if (!peer) return;
    if (msg.t === 'text') addTextItem(String(msg.body || '').slice(0, 100000), from);
    else if (msg.t === 'files') receiveRoomFiles(from, msg);
    else if (msg.t === 'got') {
      const el = $(`[data-item="${CSS.escape(msg.id)}"]`);
      if (el) { el.classList.add('delivered'); $('.msg-foot', el).textContent = `Delivered to ${peer.name} ✓`; }
    } else if (msg.t === 'bye') {
      room.peers.delete(from);
      toast(`${peer.name} left`);
      renderRoom();
    }
  }

  function renderInvite() {
    const link = roomLink();
    $('#roomLink').value = link;
    drawQR($('#roomQr'), link);
  }

  function renderRoom() {
    const n = room.peers.size;
    const status = $('#roomStatus');
    status.classList.toggle('on', !!room.me && n > 0);
    status.classList.toggle('off', !room.me);
    $('span:last-child', status).textContent = !room.me
      ? 'Connecting…'
      : n ? `${n + 1} devices connected · encrypted` : 'Waiting for another device to join…';
    $('#roomInvite').classList.toggle('collapsed', n > 0 && !room.inviteOpen);
    if (typeof syncHosting === 'function') syncHosting();
    $('#roomView').classList.toggle('paired', n > 0);

    const wrap = $('#peers');
    const want = [['me', { name: `${myDevice.name} (this device)`, kind: myDevice.kind }], ...room.peers];
    const have = new Map($$('.peer', wrap).map((el) => [el.dataset.peer, el]));
    for (const [id, el] of have) {
      if (id !== 'me' && !room.peers.has(id) && !el.classList.contains('out')) {
        el.classList.add('out');
        el.addEventListener('animationend', () => el.remove(), { once: true });
      }
    }
    for (const [id, p] of want) {
      if (have.has(id)) continue;
      wrap.append(h('span', { class: `peer${id === 'me' ? ' me' : ''}`, 'data-peer': id, style: `--h:${id === 'me' ? 265 : hueOf(id)}` },
        h('span', { class: 'peer-ico', html: DEVICE_ICON[p.kind] || DEVICE_ICON.desktop }), p.name));
    }
    updateSendState();
  }

  function endRoom(why) {
    if (room.closed) return;
    room.closed = true;
    room.abort?.abort();
    stopHosting();
    for (const s of room.shares) if (!s.gone) {
      api(`/api/s/${s.id}`, { method: 'DELETE', headers: { 'X-Owner-Token': s.ownerToken } }).catch(() => {});
      markGone(s, 'Session ended');
    }
    room.shares = [];
    try { sessionStorage.removeItem(`p:${room.id}`); } catch { /* ignore */ }
    history.replaceState(null, '', '/');
    if (why) toast(why);
    show('send');
    refreshSummary();
  }

  async function leaveRoom() {
    if (room.me) await roomSend({ t: 'bye' }).catch(() => {});
    endRoom();
  }

  // ---- feed
  const timeStr = () => new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  function feedItem(from, id) {
    const mine = from === 'me';
    const name = mine ? 'You' : room.peers.get(from)?.name || 'Device';
    const li = h('li', { class: `msg ${mine ? 'mine' : 'theirs'}`, 'data-item': id, style: `--h:${mine ? 265 : hueOf(from)}` },
      h('div', { class: 'msg-head' }, h('span', { class: 'msg-dot' }), h('b', {}, name), h('span', {}, timeStr())));
    const feed = $('#feed');
    feed.append(li);
    requestAnimationFrame(() => feed.scrollTo({ top: feed.scrollHeight, behavior: 'smooth' }));
    return li;
  }

  function addTextItem(text, from, id = rid()) {
    const li = feedItem(from, id);
    const pre = h('pre', { class: 'msg-text' }, text);
    li.append(pre, h('button', { class: 'msg-copy', title: 'Copy', html: ICON.copy, onclick: async () => { await copyText(text, pre); toast('Copied', 'ok'); } }));
    return li;
  }

  async function sendRoomText() {
    const ta = $('#roomText');
    const text = ta.value;
    if (!text.trim()) return;
    if (!room.peers.size) return toast('No device connected yet — scan the QR code on another device first');
    const id = rid();
    try {
      await roomSend({ t: 'text', id, body: text });
      ta.value = '';
      autosize();
      addTextItem(text, 'me', id);
    } catch (err) { toast(err.message, 'err'); }
  }

  async function sendRoomFiles(list, dirs = []) {
    const items = asItems(list);
    if (!items.length && !dirs.length) return;
    if (!room.peers.size) return toast('No device connected yet — scan the QR code on another device first');
    const id = rid();
    const li = feedItem('me', id);
    const total = items.reduce((s, it) => s + it.file.size, 0);
    const groups = groupItems(items, (it) => it.path, (it) => it.file.size);
    const ul = h('ul', { class: 'files' }, groups.map((g, i) => {
      if (g.kind === 'folder') {
        return h('li', { class: 'file folder-row', style: `--i:${i}` }, folderIcon(),
          h('div', { class: 'fmeta' }, h('div', { class: 'fname', title: g.name }, g.name), h('div', { class: 'fsize' }, `${g.idx.length} files · ${fmtBytes(g.size)}`)));
      }
      const f = g.items[0].file;
      return h('li', { class: 'file', style: `--i:${i}` },
        fileIcon(f.name, f.type, kindOf(f.name, f.type).k === 'img' && f.size < 25e6 ? URL.createObjectURL(f) : null),
        h('div', { class: 'fmeta' }, h('div', { class: 'fname', title: f.name }, f.name), h('div', { class: 'fsize' }, fmtBytes(f.size))));
    }));
    const bar = h('div', { class: 'fbar big' }, h('i'));
    const foot = h('div', { class: 'msg-foot' }, 'Encrypting…');
    li.append(ul, bar, foot);
    try {
      const share = await createShare(items, '', () => {}, { live: true, ttl: 1440, burn: false, dirs });
      room.shares.push(share);
      const prevServe = share.onServe;
      share.onServe = () => {
        prevServe?.();
        const p = share.chunks ? Math.min(1, share.served / share.chunks) : 1;
        const sent = Math.min(total, share.served * (share.chunk || CHUNK));
        const speed = share.pace ? share.pace(sent) : '';
        bar.style.setProperty('--p', p);
        if (!li.classList.contains('delivered')) {
          foot.textContent = p < 1
            ? `Sending · ${Math.round(p * 100)}%${speed ? ` · ${speed}` : ''}`
            : 'Sent — waiting for confirmation…';
        }
      };
      // Only the share id + key travel in the message; names and paths stay inside the encrypted manifest.
      await roomSend({ t: 'files', id, share: share.id, key: share.key });
      foot.textContent = total ? 'Sending · 0%' : 'Sent';
      if (!share.chunks) bar.style.setProperty('--p', 1);
    } catch (err) {
      foot.textContent = `Failed: ${err.message}`;
      li.classList.add('failed');
    }
  }

  async function receiveRoomFiles(from, msg) {
    const li = feedItem(from, msg.id);
    const foot = h('div', { class: 'msg-foot' }, 'Unlocking…');
    const ul = h('ul', { class: 'files' });
    li.append(ul, foot);
    let reader;
    try {
      const key = b64u.dec(String(msg.key));
      const manifest = await fetchManifest(String(msg.share), key);
      if (!manifest) throw new Error('Could not decrypt this transfer');
      reader = makeReader(String(msg.share), key, manifest);
    } catch (err) {
      foot.textContent = `Failed: ${err.message}`;
      li.classList.add('failed');
      return;
    }
    const view = renderShare(reader, ul, { preview: false });
    const n = reader.files.length;
    if (n > 1 && view.groups.length > 1) {
      let label = saveAllLabel(reader);
      const btn = h('button', { class: 'ghost small' }, label);
      saveLabels.add(() => { if (!btn.disabled && !/Saved|Saving/.test(btn.textContent)) btn.textContent = label = saveAllLabel(reader); });
      btn.addEventListener('click', async () => {
        try {
          const pending = reader.saveAll((frac, idx, p) => view.progress(idx, p));
          btn.disabled = true;
          btn.textContent = 'Saving…';
          await pending;
          reader.ack();
          btn.textContent = 'Saved ✓';
        } catch (err) {
          if (err.name !== 'AbortError') toast(err.message, 'err');
          btn.textContent = label;
        } finally { btn.disabled = false; }
      });
      li.append(btn);
    }

    if (reader.total > AUTO_RECEIVE) {
      foot.textContent = canSaveFolders || saveDest.handle
        ? `${fmtBytes(reader.total)} — tap save to stream it straight to disk. Keep the sender’s tab open.`
        : reader.total > HUGE ? hugeWarning(reader.total) : `${fmtBytes(reader.total)} — tap save to download`;
      roomSend({ t: 'got', id: msg.id }, from).catch(() => {});
      return;
    }
    // Small enough: pull and decrypt right away so it's ready the instant it lands.
    try {
      let done = 0;
      for (let idx = 0; idx < n; idx++) {
        const size = reader.files[idx].size;
        await reader.keep(idx, (p) => {
          view.progress(idx, p);
          foot.textContent = `Receiving · ${Math.round(((done + p * size) / (reader.total || 1)) * 100)}%`;
        });
        done += size;
        view.progress(idx, 1);
      }
      view.thumbs();
      foot.textContent = `Received ${fmtBytes(reader.total)} · decrypted on this device`;
      li.classList.add('delivered');
      roomSend({ t: 'got', id: msg.id }, from).catch(() => {});
      if ($('#autoSave').checked) {
        const dest = await destDir(false);
        if (dest) {
          // A remembered folder with access already granted: everything, folders included, goes straight in.
          await reader.saveAll((frac, idx, p) => view.progress(idx, p));
          foot.textContent = `Received ${fmtBytes(reader.total)} · saved to “${dest.name}”`;
        } else {
          // Loose files download straight away; folders need one tap (the browser asks where to put them).
          reader.files.forEach((f, idx) => { if (!topOf(f.path || f.name)) saveBlob(reader.kept.get(idx).blob, f.name); });
          if (reader.hasFolders) toast('Folder received — tap its save button to choose where it goes', 'ok');
        }
        reader.ack();
      }
    } catch (err) {
      foot.textContent = `Failed: ${err.message}`;
      li.classList.add('failed');
    }
  }

  // ============================================================ PAIRING CODES
  // Computer-to-computer pairing without a camera: one side shows a code like "7-291-735",
  // the other types it. "7" is a public mailbox slot; the six digits are a password for a
  // CPace PAKE (see pake.js). Both sides derive a strong key from the handshake and the
  // session key is sent across sealed with it. The digits never leave either device, a
  // passive observer can't brute-force them offline, and each code allows a single attempt.
  const pairing = { abort: null, mode: 'qr' };

  function randomDigits(n) {
    let out = '';
    while (out.length < n) { const b = nacl.randomBytes(1)[0]; if (b < 250) out += b % 10; } // unbiased
    return out;
  }

  async function pairSend(slot, token, obj, signal) {
    await api(`/api/pair/${slot}/send`, {
      method: 'POST', signal, headers: { 'X-Pair-Token': token, 'Content-Type': 'text/plain' }, body: JSON.stringify(obj),
    });
  }
  async function pairRecv(slot, token, signal) {
    for (;;) { // long-poll until the other side says something
      const res = await api(`/api/pair/${slot}/recv`, { headers: { 'X-Pair-Token': token }, signal });
      if (res.status === 200) return JSON.parse(await res.text());
    }
  }

  function showCode(code, ttl) {
    const box = $('#pairCode');
    box.textContent = '';
    [...code].forEach((ch, i) => box.append(h('span', { class: ch === '-' ? 'sep' : 'dg', style: `--i:${i}` }, ch === '-' ? '' : ch)));
    box.setAttribute('aria-label', `Pairing code ${code.split('').join(' ')}`);
    const bar = $('#codeTimer');
    bar.style.transition = 'none';
    bar.style.width = '100%';
    void bar.offsetWidth;
    bar.style.transition = `width ${ttl}ms linear`;
    bar.style.width = '0%';
    const where = (shareOrigins()[originIdx]?.origin || location.origin).replace(/^https?:\/\//, '');
    $('#codeStatus').textContent = `On the other computer, open ${where} and type this code under “Have a pairing code?”.`;
  }

  function stopHosting() { pairing.abort?.abort(); pairing.abort = null; }

  async function hostPairing() {
    stopHosting();
    const ctl = new AbortController();
    pairing.abort = ctl;
    const { signal } = ctl;
    $('#pairCode').textContent = '';
    while (!signal.aborted && !room.closed) {
      let slot = null;
      let token = null;
      try {
        const pass = randomDigits(6);
        const sid = nacl.randomBytes(16);
        const st = CPace.start(pass, sid);
        const r = await (await api('/api/pair', { method: 'POST', signal })).json();
        ({ slot, token } = r);
        showCode(`${slot}-${pass.slice(0, 3)}-${pass.slice(3)}`, r.ttl);
        await pairSend(slot, token, { sid: b64u.enc(sid), Y: b64u.enc(st.Y) }, signal);
        const m = await pairRecv(slot, token, signal); // the other computer's answer
        let keys = null;
        try {
          keys = CPace.finish(st, sid, b64u.dec(m.Y), true);
          if (!nacl.verify(keys.guestTag, b64u.dec(m.tag || ''))) keys = null;
        } catch { keys = null; }
        if (!keys) {
          await pairSend(slot, token, { fail: true }, signal).catch(() => {});
          toast('A wrong code was entered — that code is now void. Here’s a fresh one.', 'err');
          continue;
        }
        const nonce = nacl.randomBytes(NONCE);
        const sealed = nacl.secretbox(new TextEncoder().encode(JSON.stringify({ room: room.id, key: b64u.enc(room.key) })), nonce, keys.key);
        const box = new Uint8Array(NONCE + sealed.length);
        box.set(nonce);
        box.set(sealed, NONCE);
        await pairSend(slot, token, { tag: b64u.enc(keys.hostTag), box: b64u.enc(box) }, signal);
        toast('Code accepted — connecting the other computer…', 'ok');
        slot = null; // used up; the guest closes the mailbox
      } catch (err) {
        if (signal.aborted) break;
        if (err.status !== 404 && err.status !== 410) await sleep(1500); // expired codes just roll over
      } finally {
        if (slot && signal.aborted) api(`/api/pair/${slot}`, { method: 'DELETE', headers: { 'X-Pair-Token': token } }).catch(() => {});
      }
    }
  }

  $('#inviteSeg').addEventListener('click', (e) => {
    const btn = e.target.closest('.seg-btn');
    if (!btn) return;
    pairing.mode = btn.dataset.invite;
    $('#inviteSeg').dataset.mode = pairing.mode;
    $$('#inviteSeg .seg-btn').forEach((b) => { b.classList.toggle('active', b === btn); b.setAttribute('aria-selected', b === btn); });
    $$('.invite-pane').forEach((p) => p.classList.toggle('hidden', p.dataset.pane !== pairing.mode));
    syncHosting();
  });

  // Only run a pairing code while the Code tab is actually visible.
  function syncHosting() {
    const visible = !room.closed && pairing.mode === 'code' && !$('#roomInvite').classList.contains('collapsed');
    if (visible && !pairing.abort) hostPairing();
    else if (!visible && pairing.abort) stopHosting();
  }

  // ---- joining with a code (home page)
  const codeForm = $('#codeJoin');
  const codeInput = $('#codeInput');
  const codeDigits = () => codeInput.value.replace(/\D/g, '');
  const CODE_HINT = 'Shown on the other computer under <b>Pair a device → Code</b>.';
  codeInput.addEventListener('input', () => {
    $('#codeGo').disabled = codeDigits().length < 7;
    codeForm.classList.remove('bad');
  });
  codeForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const d = codeDigits();
    if (d.length < 7 || codeForm.classList.contains('busy')) return;
    if (typeof CPace === 'undefined' || typeof nacl === 'undefined') return toast('Encryption library failed to load', 'err');
    const slot = String(parseInt(d.slice(0, -6), 10));
    const pass = d.slice(-6);
    const hint = $('#codeHint');
    codeForm.classList.add('busy');
    codeForm.classList.remove('bad');
    hint.textContent = 'Connecting securely…';
    let token = null;
    try {
      ({ token } = await (await api(`/api/pair/${slot}/claim`, { method: 'POST' })).json());
      const m1 = await pairRecv(slot, token);
      const sid = b64u.dec(m1.sid);
      const st = CPace.start(pass, sid);
      const keys = CPace.finish(st, sid, b64u.dec(m1.Y), false);
      await pairSend(slot, token, { Y: b64u.enc(st.Y), tag: b64u.enc(keys.guestTag) });
      const m2 = await pairRecv(slot, token);
      if (m2.fail || !nacl.verify(keys.hostTag, b64u.dec(m2.tag || ''))) throw new Error('That code didn’t match. It’s now void — ask for a new one.');
      const box = b64u.dec(m2.box);
      const plain = nacl.secretbox.open(box.subarray(NONCE), box.subarray(0, NONCE), keys.key);
      if (!plain) throw new Error('Pairing failed — please try again');
      const { room: roomId, key } = JSON.parse(new TextDecoder().decode(plain));
      codeInput.value = '';
      $('#codeGo').disabled = true;
      hint.innerHTML = CODE_HINT;
      enterRoom(roomId, b64u.dec(key));
    } catch (err) {
      codeForm.classList.remove('bad');
      void codeForm.offsetWidth;
      codeForm.classList.add('bad');
      hint.textContent = err.message;
    } finally {
      if (token) api(`/api/pair/${slot}`, { method: 'DELETE', headers: { 'X-Pair-Token': token } }).catch(() => {});
      codeForm.classList.remove('busy');
    }
  });

  // ---- composer
  const roomText = $('#roomText');
  function autosize() { roomText.style.height = 'auto'; roomText.style.height = `${Math.min(roomText.scrollHeight, 160)}px`; }
  function updateSendState() { $('#roomSendBtn').disabled = !roomText.value.trim(); }
  roomText.addEventListener('input', () => { autosize(); updateSendState(); });
  roomText.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); sendRoomText().then(updateSendState); }
  });
  $('#roomSendBtn').addEventListener('click', () => sendRoomText().then(updateSendState));
  $('#roomAttach').addEventListener('click', () => $('#roomFiles').click());
  $('#roomFiles').addEventListener('change', (e) => { sendRoomFiles(e.target.files); e.target.value = ''; });
  $('#roomFolder').addEventListener('change', (e) => { sendRoomFiles(e.target.files); e.target.value = ''; });
  $('#roomFolderBtn').addEventListener('click', () => $('#roomFolder').click());
  if (!('webkitdirectory' in $('#roomFolder'))) $('#roomFolderBtn').remove();
  $('#roomInviteBtn').addEventListener('click', () => { room.inviteOpen = !room.inviteOpen; renderRoom(); });
  $('#roomLeaveBtn').addEventListener('click', leaveRoom);
  $('#roomCopy').addEventListener('click', async () => { await copyText($('#roomLink').value, $('#roomLink')); toast('Session link copied — it contains the key', 'ok'); });
  $('#pairBtn').addEventListener('click', startRoom);
  try { $('#autoSave').checked = localStorage.getItem('autoSave') === '1'; } catch { /* ignore */ }
  $('#autoSave').addEventListener('change', (e) => { try { localStorage.setItem('autoSave', e.target.checked ? '1' : '0'); } catch { /* ignore */ } });

  // Leaving mid-transfer would cut the other device off — warn first.
  window.addEventListener('beforeunload', (e) => {
    if (!room.closed && room.shares.some((s) => !s.gone && s.served < s.chunks)) { e.preventDefault(); e.returnValue = ''; }
  });

  // ============================================================ boot
  loadSaveDest();
  const route = location.pathname.match(/^\/([rp])\/([A-Za-z0-9_-]{22})$/);
  if (route?.[1] === 'r') receive(route[2]);
  else if (route?.[1] === 'p') {
    let keyStr = location.hash.slice(1);
    if (!keyStr) { try { keyStr = sessionStorage.getItem(`p:${route[2]}`) || ''; } catch { /* ignore */ } }
    let key = null;
    try { key = b64u.dec(keyStr); } catch { /* bad key */ }
    infoReady.then(() => {
      if (key?.length === 32 && typeof nacl !== 'undefined') enterRoom(route[2], key);
      else { history.replaceState(null, '', '/'); show('send'); refreshSummary(); toast('That session link is incomplete — scan the QR code again', 'err'); }
    });
  } else { show('send'); refreshSummary(); }
})();
