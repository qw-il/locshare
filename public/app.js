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

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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
    if (currentView?.id === 'view-room' && e.dataTransfer?.files.length) return sendRoomFiles(e.dataTransfer.files);
    if (currentView?.id !== 'view-send' || !e.dataTransfer?.files.length) return;
    if (state.mode !== 'files') $('[data-mode="files"]').click();
    addFiles(e.dataTransfer.files);
  });
  window.addEventListener('paste', (e) => {
    if (currentView?.id === 'view-room' && e.clipboardData?.files.length) { e.preventDefault(); return sendRoomFiles(e.clipboardData.files); }
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

  async function createShare(files, note, onProgress, opts = {}) {
    await infoReady;
    const ttl = opts.ttl ?? state.ttl;
    const burn = opts.burn ?? state.burn;
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
    const fresh = opts.live ? info : await api('/api/info').then((r) => r.json()).catch(() => info);
    let live = !!opts.live || bytes > fresh.freeBytes;
    const open = (asLive) => api('/api/s', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ttl, burn, bytes, live: asLive }),
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
        note: note || undefined, burn, created: Date.now(),
      }, key);
      const sealed = await (await api(`/api/s/${id}/m`, { method: 'PUT', headers: { ...auth, 'X-Chunk-Count': String(chunks) }, body: manifest })).json();
      onProgress(1);

      const label = files.length
        ? (files.length === 1 ? files[0].name : `${files[0].name} + ${files.length - 1} more`)
        : 'Private note';
      const share = { id, ownerToken, key: b64u.enc(key), label, expiresAt: sealed.expiresAt, ttlMs: ttl * 60e3, burn, opens: 0, downloads: 0, gone: false, live, senderOnline: false, chunks, served: 0 };
      if (live) {
        // Don't hand out the link until this tab is ready to answer block requests.
        await Promise.race([new Promise((r) => { share.onReady = r; runLive(share, sealChunk); }), sleep(8000)]);
      }
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
          .then((r) => { if (r.ok) { share.served++; share.onServe?.(); } })
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

  // ============================================================ share reader
  // Shared by the one-off receive page and live sessions: decrypts a share's files on demand.

  async function fetchManifest(id, key) {
    const bytes = new Uint8Array(await (await api(`/api/s/${id}/m`)).arrayBuffer());
    return openManifest(bytes, key);
  }

  function makeReader(id, key, manifest) {
    const prefix = b64u.dec(manifest.prefix);
    const C = manifest.chunkSize;
    const files = manifest.files;
    const total = files.reduce((s, f) => s + f.size, 0);
    const kept = new Map(); // idx -> { blob, crc }: decrypted copies held in memory

    async function getChunk(i) {
      for (let attempt = 0; ; attempt++) {
        try {
          const buf = new Uint8Array(await (await api(`/api/s/${id}/c/${i}`)).arrayBuffer());
          // Always use the nonce *we* expect for this index — blocks can't be swapped or reordered.
          const plain = nacl.secretbox.open(buf.subarray(NONCE), chunkNonce(prefix, i), key);
          if (!plain) throw Object.assign(new Error('Integrity check failed — data was tampered with'), { fatal: true });
          return plain;
        } catch (err) {
          // A live sender can blip (tab reconnecting, phone busy): retry briefly before giving up.
          if (err.fatal || err.status === 404 || err.status === 410 || attempt >= 4) throw err;
          await sleep(700 * (attempt + 1));
        }
      }
    }

    // Decrypt one file block by block, in order, with a few blocks fetched ahead.
    // Each piece is handed to `write` and can be dropped right after — memory use stays flat.
    async function streamFile(idx, write, onProgress, wantCrc) {
      const f = files[idx];
      if (kept.has(idx)) { const k = kept.get(idx); await write(k.blob); onProgress?.(1); return k.crc; }
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

    // Decrypt into memory (for previews and instant saves).
    async function keep(idx, onProgress) {
      if (kept.has(idx)) { onProgress?.(1); return kept.get(idx); }
      const parts = [];
      const crc = await streamFile(idx, (d) => { parts.push(d); }, onProgress, true);
      const r = { blob: new Blob(parts, { type: files[idx].type || 'application/octet-stream' }), crc };
      kept.set(idx, r);
      return r;
    }

    // NB: must be called straight from a click handler — the save dialog needs the user gesture.
    async function saveFile(idx, onProgress) {
      const f = files[idx];
      if (kept.has(idx)) { saveBlob(kept.get(idx).blob, f.name); onProgress?.(1); return; }
      const sink = await openSink(f.name, f.type);
      try { await streamFile(idx, (d) => sink.write(d), onProgress); await sink.close(); } catch (e) { sink.abort(); throw e; }
    }

    async function saveAll(onProgress) {
      if (files.length === 1) return saveFile(0, (p) => onProgress?.(p, 0, p));
      const sink = await openSink(`locshare-${new Date().toISOString().slice(0, 10)}.zip`, 'application/zip');
      try {
        const zip = zipWriter(sink);
        let doneBytes = 0;
        for (let idx = 0; idx < files.length; idx++) {
          const f = files[idx];
          await zip.add(f.name, f.size, (write) => streamFile(idx, write, (p) => onProgress?.(total ? (doneBytes + p * f.size) / total : 1, idx, p), true));
          doneBytes += f.size;
        }
        await zip.finish();
      } catch (e) { sink.abort(); throw e; }
    }

    return { id, manifest, files, total, kept, keep, saveFile, saveAll, ack: () => api(`/api/s/${id}/a`, { method: 'POST' }).catch(() => {}) };
  }

  // One file row with a progress bar and a save button.
  function fileRow(reader, idx, opts = {}) {
    const f = reader.files[idx];
    const bar = h('div', { class: 'fbar' }, h('i'));
    bar.style.display = 'none';
    const icon = fileIcon(f.name, f.type);
    const btn = opts.button === false ? null : h('button', { class: 'dl-btn', title: 'Save', 'aria-label': `Save ${f.name}`, html: ICON.dl });
    const li = h('li', { class: 'file', style: `--i:${idx}` },
      icon,
      h('div', { class: 'fmeta' }, h('div', { class: 'fname', title: f.name }, f.name), h('div', { class: 'fsize' }, fmtBytes(f.size)), bar),
      btn);
    const progress = (p) => { bar.style.display = ''; bar.style.setProperty('--p', p); };
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
        } catch (err) {
          if (err.name !== 'AbortError') toast(err.message, 'err');
          btn.innerHTML = ICON.dl;
        } finally { btn.disabled = false; }
      });
    }
    if (opts.preview !== false) thumb();
    return { li, progress, icon, btn, thumb };
  }

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
    title.textContent = fileCount ? `${fileCount} file${fileCount > 1 ? 's' : ''} for you` : 'A private note for you';
    sub.textContent = manifest.burn
      ? 'This share self-destructs once saved. Make sure you’re ready.'
      : 'Decrypted locally in this browser. The host never saw any of it.';

    if (manifest.note) {
      $('#noteText').textContent = manifest.note;
      $('#noteOut').classList.remove('hidden');
      $('#noteCopy').onclick = async () => { await copyText(manifest.note, $('#noteText')); toast('Note copied', 'ok'); };
    }

    // Self-destructing shares get no per-file buttons or previews: one save, then gone.
    const rows = manifest.files.map((_, idx) => {
      const row = fileRow(reader, idx, { button: !manifest.burn, preview: !manifest.burn });
      $('#recvList').append(row.li);
      return row;
    });

    $('#recvMeta').textContent = `${fileCount ? `${fmtBytes(reader.total)} · ` : ''}verified & decrypted on this device`;

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
        if (saveAll.classList.contains('busy') || saveAll.disabled) return;
        try {
          const pending = reader.saveAll((frac, idx, p) => {
            rows[idx].progress(p);
            setProgress(saveAll, frac, `Decrypting · ${Math.round(frac * 100)}%`);
          });
          saveAll.classList.add('busy');
          await pending;
          setProgress(saveAll, 1, 'Saved');
          toast(`Saved ${fileCount > 1 ? `${fileCount} files` : manifest.files[0].name}`, 'ok');
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

  async function sendRoomFiles(list) {
    const files = [...list];
    if (!files.length) return;
    if (!room.peers.size) return toast('No device connected yet — scan the QR code on another device first');
    const id = rid();
    const li = feedItem('me', id);
    const total = files.reduce((s, f) => s + f.size, 0);
    const ul = h('ul', { class: 'files' }, files.map((f, i) => h('li', { class: 'file', style: `--i:${i}` },
      fileIcon(f.name, f.type, kindOf(f.name, f.type).k === 'img' && f.size < 25e6 ? URL.createObjectURL(f) : null),
      h('div', { class: 'fmeta' }, h('div', { class: 'fname', title: f.name }, f.name), h('div', { class: 'fsize' }, fmtBytes(f.size))))));
    const bar = h('div', { class: 'fbar big' }, h('i'));
    const foot = h('div', { class: 'msg-foot' }, 'Encrypting…');
    li.append(ul, bar, foot);
    try {
      const share = await createShare(files, '', () => {}, { live: true, ttl: 1440, burn: false });
      room.shares.push(share);
      share.onServe = () => {
        const p = share.chunks ? Math.min(1, share.served / share.chunks) : 1;
        bar.style.setProperty('--p', p);
        if (!li.classList.contains('delivered')) foot.textContent = p < 1 ? `Sending · ${Math.round(p * 100)}%` : 'Sent — waiting for confirmation…';
      };
      await roomSend({ t: 'files', id, share: share.id, key: share.key, files: files.map((f) => ({ name: f.name, size: f.size, type: f.type })) });
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
    const rows = reader.files.map((_, idx) => { const r = fileRow(reader, idx, { preview: false }); ul.append(r.li); return r; });
    const n = reader.files.length;
    if (n > 1) {
      const btn = h('button', { class: 'ghost small' }, `Save all ${n} (.zip)`);
      btn.addEventListener('click', async () => {
        try {
          const pending = reader.saveAll((frac, idx, p) => rows[idx].progress(p));
          btn.disabled = true;
          btn.textContent = 'Saving…';
          await pending;
          reader.ack();
          btn.textContent = 'Saved ✓';
        } catch (err) {
          if (err.name !== 'AbortError') toast(err.message, 'err');
          btn.textContent = `Save all ${n} (.zip)`;
        } finally { btn.disabled = false; }
      });
      li.append(btn);
    }

    if (reader.total > AUTO_RECEIVE) {
      foot.textContent = `${fmtBytes(reader.total)} — tap save to stream it straight to disk`;
      roomSend({ t: 'got', id: msg.id }, from).catch(() => {});
      return;
    }
    // Small enough: pull and decrypt right away so it's ready the instant it lands.
    try {
      let done = 0;
      for (let idx = 0; idx < n; idx++) {
        const size = reader.files[idx].size;
        await reader.keep(idx, (p) => {
          rows[idx].progress(p);
          foot.textContent = `Receiving · ${Math.round(((done + p * size) / (reader.total || 1)) * 100)}%`;
        });
        done += size;
        rows[idx].progress(1);
        rows[idx].thumb();
      }
      foot.textContent = `Received ${fmtBytes(reader.total)} · decrypted on this device`;
      li.classList.add('delivered');
      roomSend({ t: 'got', id: msg.id }, from).catch(() => {});
      if ($('#autoSave').checked) {
        reader.files.forEach((f, idx) => saveBlob(reader.kept.get(idx).blob, f.name));
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
