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
  // XSalsa20-Poly1305 (NaCl secretbox). Works in plain-http LAN pages, where WebCrypto is unavailable.
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
        let name = rawName.replace(/[\\/]/g, '_') || 'file';
        for (let i = 2; used.has(name); i++) name = rawName.replace(/(\.[^.]*)?$/, ` (${i})$1`);
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
        files.push({ nb, size, crc, start });
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
    x: '<svg viewBox="0 0 24 24"><path d="M6 6l12 12M18 6L6 18"/></svg>',
    dl: '<svg viewBox="0 0 24 24"><path d="M12 4v11m0 0l-4.5-4.5M12 15l4.5-4.5"/><path d="M5 19h14"/></svg>',
    ok: '<svg viewBox="0 0 24 24"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>',
    spin: '<svg viewBox="0 0 24 24"><path d="M12 3a9 9 0 109 9"><animateTransform attributeName="transform" type="rotate" from="0 12 12" to="360 12 12" dur="0.8s" repeatCount="indefinite"/></path></svg>',
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
  let info = { chunkSize: CHUNK, ttlChoices: [5, 15, 60, 360, 1440], origins: [] };
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
  fileInput.addEventListener('change', () => { addFiles(fileInput.files); fileInput.value = ''; });
  drop.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); } });
  let dragDepth = 0;
  window.addEventListener('dragenter', (e) => { if (currentView?.id !== 'view-send') return; e.preventDefault(); dragDepth++; drop.classList.add('over'); });
  window.addEventListener('dragleave', () => { if (--dragDepth <= 0) { dragDepth = 0; drop.classList.remove('over'); } });
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', (e) => {
    e.preventDefault();
    dragDepth = 0;
    drop.classList.remove('over');
    if (currentView?.id !== 'view-send' || !e.dataTransfer?.files.length) return;
    if (state.mode !== 'files') $('[data-mode="files"]').click();
    addFiles(e.dataTransfer.files);
  });
  window.addEventListener('paste', (e) => {
    if (currentView?.id !== 'view-send' || !e.clipboardData?.files.length) return;
    e.preventDefault();
    if (state.mode !== 'files') $('[data-mode="files"]').click();
    addFiles(e.clipboardData.files);
  });

  function addFiles(list) {
    if (state.busy) return;
    const start = state.files.length;
    for (const f of list) {
      if (state.files.some((x) => x.name === f.name && x.size === f.size && x.lastModified === f.lastModified)) continue;
      state.files.push(f);
      const thumb = kindOf(f.name, f.type).k === 'img' && f.size < 25e6 ? URL.createObjectURL(f) : null;
      const li = h('li', { class: 'file', style: `--i:${state.files.length - 1 - start}` },
        fileIcon(f.name, f.type, thumb),
        h('div', { class: 'fmeta' }, h('div', { class: 'fname', title: f.name }, f.name), h('div', { class: 'fsize' }, fmtBytes(f.size))),
        h('button', { class: 'x-btn', title: 'Remove', 'aria-label': `Remove ${f.name}`, html: ICON.x, onclick: () => removeFile(f, li, thumb) }),
      );
      fileList.append(li);
    }
    refreshSummary();
  }
  function removeFile(f, li, thumb) {
    if (state.busy) return;
    state.files = state.files.filter((x) => x !== f);
    li.classList.add('out');
    li.addEventListener('animationend', () => li.remove(), { once: true });
    if (thumb) URL.revokeObjectURL(thumb);
    refreshSummary();
  }
  function clearFiles() {
    state.files = [];
    $$('img', fileList).forEach((i) => URL.revokeObjectURL(i.src));
    fileList.textContent = '';
    $('#noteInput').value = '';
    refreshSummary();
  }

  $('#noteInput').addEventListener('input', refreshSummary);

  function payload() {
    const note = state.mode === 'note' ? $('#noteInput').value : '';
    const files = state.mode === 'files' ? state.files : [];
    return { files, note };
  }
  function refreshSummary() {
    const { files, note } = payload();
    drop.classList.toggle('compact', state.files.length > 0);
    const total = files.reduce((s, f) => s + f.size, 0);
    const ok = files.length > 0 || note.trim().length > 0;
    shareBtn.disabled = !ok || state.busy;
    let msg = 'Add a file or write a note to begin.';
    if (files.length) {
      const padded = Math.ceil(total / CHUNK) * CHUNK;
      msg = `${files.length} file${files.length > 1 ? 's' : ''} · ${fmtBytes(total)} — the host will only see ~${fmtBytes(padded || 0)} of noise`;
      if (padded > info.freeBytes) msg = `${files.length} file${files.length > 1 ? 's' : ''} · ${fmtBytes(total)} — streams live from this tab, nothing stored on the host`;
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
    const { files, note } = payload();
    if (!files.length && !note.trim()) return;
    state.busy = true;
    shareBtn.disabled = false;
    shareBtn.classList.add('busy');
    setProgress(shareBtn, 0, 'Generating key…');
    try {
      const share = await createShare(files, note, (p) => setProgress(shareBtn, p, `Encrypting & sending · ${Math.round(p * 100)}%`));
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

  async function createShare(files, note, onProgress) {
    await infoReady;
    const key = nacl.randomBytes(32);
    const prefix = nacl.randomBytes(16);
    const entries = [];
    let total = 0;
    for (const f of files) {
      entries.push({ name: f.name, type: f.type, size: f.size, offset: total, modified: f.lastModified });
      total += f.size;
    }
    const chunks = Math.ceil(total / CHUNK);
    const bytes = chunks * (CHUNK + 40);

    // No size limit: if the host can't hold the share in RAM, stream it live from this tab instead.
    const fresh = await api('/api/info').then((r) => r.json()).catch(() => info);
    let live = bytes > fresh.freeBytes;
    const open = (asLive) => api('/api/s', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ttl: state.ttl, burn: state.burn, bytes, live: asLive }),
    });
    let res;
    try { res = await open(live); } catch (err) {
      if (err.status !== 507) throw err;
      live = true;
      res = await open(true);
    }
    const { id, ownerToken } = await res.json();
    const auth = { 'X-Owner-Token': ownerToken };

    // Build chunk i from the virtual concatenation of all files, padded with zeros to CHUNK bytes.
    async function readChunk(i) {
      const start = i * CHUNK;
      const end = Math.min(start + CHUNK, total);
      const parts = [];
      for (let k = 0; k < files.length; k++) {
        const e = entries[k];
        const a = Math.max(start, e.offset);
        const b = Math.min(end, e.offset + e.size);
        if (a < b) parts.push(files[k].slice(a - e.offset, b - e.offset));
      }
      const buf = new Uint8Array(CHUNK);
      buf.set(new Uint8Array(await new Blob(parts).arrayBuffer()), 0);
      return buf;
    }

    const sealChunk = async (i) => {
      const plain = await readChunk(i);
      const body = seal(plain, chunkNonce(prefix, i), key);
      plain.fill(0);
      return body;
    };

    let done = 0;
    onProgress(0);
    try {
      if (!live) await pool(chunks, 3, async (i) => {
        const plain = await readChunk(i);
        const body = seal(plain, chunkNonce(prefix, i), key);
        plain.fill(0);
        await api(`/api/s/${id}/c/${i}`, { method: 'PUT', headers: auth, body });
        onProgress(++done / chunks);
      });

      const manifest = sealManifest({
        v: 1, prefix: b64u.enc(prefix), chunkSize: CHUNK, chunks, total, files: entries,
        note: note || undefined, burn: state.burn, created: Date.now(),
      }, key);
      const sealed = await (await api(`/api/s/${id}/m`, { method: 'PUT', headers: { ...auth, 'X-Chunk-Count': String(chunks) }, body: manifest })).json();
      onProgress(1);

      const label = files.length
        ? (files.length === 1 ? files[0].name : `${files[0].name} + ${files.length - 1} more`)
        : 'Private note';
      const share = { id, ownerToken, key: b64u.enc(key), label, expiresAt: sealed.expiresAt, ttlMs: state.ttl * 60e3, burn: state.burn, opens: 0, downloads: 0, gone: false, live, senderOnline: false };
      if (live) runLive(share, sealChunk);
      return share;
    } catch (err) {
      api(`/api/s/${id}`, { method: 'DELETE', headers: auth }).catch(() => {});
      throw err;
    }
  }

  // Live shares: keep a channel open to the host and answer block requests from this tab's files.
  async function runLive(share, sealChunk) {
    const auth = { 'X-Owner-Token': share.ownerToken };
    share.abort = new AbortController();
    let active = 0;
    const queue = [];
    const pump = () => {
      while (active < 4 && queue.length) {
        const [reqId, i] = queue.shift();
        active++;
        sealChunk(i)
          .then((body) => fetch(`/api/s/${share.id}/c/${i}?r=${reqId}`, { method: 'PUT', headers: auth, body, cache: 'no-store', signal: share.abort.signal }))
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
            if (line === 'ready') share.senderOnline = true;
            const m = line.match(/^need (\S+) (\d+)$/);
            if (m) { queue.push([m[1], +m[2]]); pump(); }
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
      if (s.live) bits.push('live · keep tab open');
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

  // ============================================================ RECEIVE
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
      const bytes = new Uint8Array(await (await api(`/api/s/${id}/m`)).arrayBuffer());
      manifest = openManifest(bytes, key);
    } catch (err) {
      forget();
      return failWith('Nothing here', err.status === 404 ? 'This share has expired, been revoked, or already self-destructed.' : err.message);
    }
    if (!manifest) return failWith('Wrong key', 'The link’s key doesn’t match this share. Nothing could be decrypted.');

    const prefix = b64u.dec(manifest.prefix);
    const C = manifest.chunkSize;
    await new Promise((r) => setTimeout(r, 450)); // let the unlock animation breathe
    lock.className = 'lock open';

    const fileCount = manifest.files.length;
    title.textContent = fileCount ? `${fileCount} file${fileCount > 1 ? 's' : ''} for you` : 'A private note for you';
    sub.textContent = manifest.burn
      ? 'This share self-destructs once saved. Make sure you’re ready.'
      : 'Decrypted locally in this browser. The host never saw any of it.';

    if (manifest.note) {
      $('#noteText').textContent = manifest.note;
      $('#noteOut').classList.remove('hidden');
      $('#noteCopy').onclick = async () => {
        try { await navigator.clipboard.writeText(manifest.note); } catch {
          const r = document.createRange(); r.selectNodeContents($('#noteText'));
          getSelection().removeAllRanges(); getSelection().addRange(r); document.execCommand('copy'); getSelection().removeAllRanges();
        }
        toast('Note copied', 'ok');
      };
    }

    async function getChunk(i) {
      const buf = new Uint8Array(await (await api(`/api/s/${id}/c/${i}`)).arrayBuffer());
      // Always use the nonce *we* expect for this index — blocks can't be swapped or reordered.
      const plain = nacl.secretbox.open(buf.subarray(NONCE), chunkNonce(prefix, i), key);
      if (!plain) throw new Error('Integrity check failed — data was tampered with');
      return plain;
    }

    // Decrypt one file block by block, in order, with a few blocks fetched ahead.
    // Each piece is handed to `write` and can be dropped right after — memory use stays flat.
    async function streamFile(idx, write, onProgress, wantCrc) {
      const f = manifest.files[idx];
      if (previews.has(idx)) { const p = previews.get(idx); await write(p.blob); onProgress?.(1); return p.crc; }
      if (f.size === 0) { onProgress?.(1); return 0; }
      const first = Math.floor(f.offset / C);
      const n = Math.floor((f.offset + f.size - 1) / C) - first + 1;
      const AHEAD = 4;
      const inflight = new Map();
      const start = (k) => { const pr = getChunk(first + k); pr.catch(() => {}); inflight.set(k, pr); };
      for (let k = 0; k < Math.min(AHEAD, n); k++) start(k);
      let crc = 0;
      for (let k = 0; k < n; k++) {
        const plain = await inflight.get(k);
        inflight.delete(k);
        if (k + AHEAD < n) start(k + AHEAD);
        const i = first + k;
        const part = plain.subarray(Math.max(f.offset, i * C) - i * C, Math.min(f.offset + f.size, (i + 1) * C) - i * C);
        if (wantCrc) crc = crc32(part, crc);
        await write(part);
        onProgress?.((k + 1) / n);
      }
      return crc;
    }

    const previews = new Map(); // idx -> { blob, crc } for small images shown inline

    const ack = () => api(`/api/s/${id}/a`, { method: 'POST' }).catch(() => {});

    // file list
    const list = $('#recvList');
    const rows = manifest.files.map((f, idx) => {
      const bar = h('i');
      const btn = manifest.burn ? null : h('button', { class: 'dl-btn', title: 'Save', 'aria-label': `Save ${f.name}`, html: ICON.dl });
      const icon = fileIcon(f.name, f.type);
      const li = h('li', { class: 'file', style: `--i:${idx}` },
        icon,
        h('div', { class: 'fmeta' },
          h('div', { class: 'fname', title: f.name }, f.name),
          h('div', { class: 'fsize' }, fmtBytes(f.size)),
          h('div', { class: 'fbar' }, bar)),
        btn);
      bar.parentElement.style.display = 'none';
      if (btn) {
        btn.addEventListener('click', async () => {
          if (btn.disabled) return;
          btn.disabled = true;
          let sink;
          try {
            sink = await openSink(f.name, f.type);
            btn.innerHTML = ICON.spin;
            bar.parentElement.style.display = '';
            await streamFile(idx, (d) => sink.write(d), (p) => bar.parentElement.style.setProperty('--p', p));
            await sink.close();
            ack();
            btn.classList.add('done');
            btn.innerHTML = ICON.ok;
          } catch (err) {
            sink?.abort();
            if (err.name !== 'AbortError') toast(err.message, 'err');
            btn.innerHTML = ICON.dl;
          } finally { btn.disabled = false; }
        });
      }
      list.append(li);
      return { li, bar, icon };
    });

    // Small images get a locally-decrypted preview (skipped for self-destructing shares).
    if (!manifest.burn) {
      manifest.files.forEach((f, idx) => {
        if (kindOf(f.name, f.type).k === 'img' && f.size <= 6e6 && !/svg/.test(f.type)) {
          const parts = [];
          streamFile(idx, (d) => parts.push(d), null, true).then((crc) => {
            const blob = new Blob(parts, { type: f.type });
            previews.set(idx, { blob, crc });
            setThumb(rows[idx].icon, URL.createObjectURL(blob));
          }).catch(() => {});
        }
      });
    }

    const total = manifest.files.reduce((s, f) => s + f.size, 0);
    $('#recvMeta').textContent = `${fileCount ? `${fmtBytes(total)} · ` : ''}verified & decrypted on this device`;

    // Note-only self-destructing share: burn right away, the note is already on screen.
    if (manifest.burn && !fileCount) {
      api(`/api/s/${id}`, { method: 'DELETE' }).catch(() => {});
      forget();
      sub.textContent = 'This note has been wiped from the host. Copy it now — it won’t be shown again.';
      return;
    }

    const saveAll = $('#saveAllBtn');
    if (fileCount > 1 || manifest.burn) {
      saveAll.classList.remove('hidden');
      $('.cta-text', saveAll).textContent = manifest.burn
        ? (fileCount > 1 ? 'Decrypt & save all (.zip)' : 'Decrypt & save')
        : 'Save all as .zip';
      saveAll.onclick = async () => {
        if (saveAll.classList.contains('busy')) return;
        const single = fileCount === 1;
        let sink;
        try {
          sink = await openSink(single ? manifest.files[0].name : `locshare-${new Date().toISOString().slice(0, 10)}.zip`,
            single ? manifest.files[0].type : 'application/zip');
          saveAll.classList.add('busy');
          let doneBytes = 0;
          const each = async (idx, write, wantCrc) => {
            const f = manifest.files[idx];
            rows[idx].bar.parentElement.style.display = '';
            const crc = await streamFile(idx, write, (p) => {
              rows[idx].bar.parentElement.style.setProperty('--p', p);
              const frac = total ? (doneBytes + p * f.size) / total : 1;
              setProgress(saveAll, frac, `Decrypting · ${Math.round(frac * 100)}%`);
            }, wantCrc);
            doneBytes += f.size;
            return crc;
          };
          if (single) {
            await each(0, (d) => sink.write(d), false);
            await sink.close();
          } else {
            const zip = zipWriter(sink);
            for (let idx = 0; idx < fileCount; idx++) {
              await zip.add(manifest.files[idx].name, manifest.files[idx].size, (write) => each(idx, write, true));
            }
            await zip.finish();
          }
          setProgress(saveAll, 1, 'Saved');
          if (!manifest.burn) ack();
          toast(`Saved ${fileCount > 1 ? `${fileCount} files` : manifest.files[0].name}`, 'ok');
          if (manifest.burn) {
            await api(`/api/s/${id}`, { method: 'DELETE' }).catch(() => {});
            forget();
            previews.clear();
            sub.textContent = 'Saved. The share has self-destructed and was wiped from the host.';
            saveAll.disabled = true;
            setProgress(saveAll, 1, 'Destroyed ✓');
          }
        } catch (err) {
          sink?.abort();
          if (err.name === 'AbortError') return;
          toast(err.message, 'err');
          setProgress(saveAll, 0, 'Try again');
        } finally {
          saveAll.classList.remove('busy');
        }
      };
    }
  }

  // ============================================================ boot
  const route = location.pathname.match(/^\/r\/([A-Za-z0-9_-]{22})$/);
  if (route) receive(route[1]);
  else { show('send'); refreshSummary(); }
})();
