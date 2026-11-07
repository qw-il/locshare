# LocShare

Private file sharing over your local network. Drop files or write a note on one device, then scan the QR code on another. Your files are encrypted before they leave your device. The machine running LocShare only ever holds scrambled bytes.

## Quick start

```bash
npm install
npm start
```

The server prints addresses such as `http://192.168.1.20:8080`. Open one in a browser on any device on the same Wi‑Fi/LAN.

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | Port to listen on |
| `HOST` | `0.0.0.0` | Interface to bind |
| `MAX_STORE_MB` | `2048` | RAM budget for all shares combined |
| `TLS_CERT` / `TLS_KEY` | — | Serve over HTTPS (recommended, see below) |

## How privacy is protected

- **End-to-end encryption.** Files, file names, types, sizes and notes are encrypted in the browser with XSalsa20‑Poly1305 (NaCl `secretbox`, via [tweetnacl](https://github.com/dchest/tweetnacl-js)). A fresh random 256‑bit key is generated for every share.
- **The key never reaches the server.** It is placed after the `#` in the link (`/r/<id>#<key>`), and browsers never send that part over the network. When the recipient opens the link, the key is moved into tab-scoped memory and removed from the address bar and browser history.
- **Sizes are hidden.** Data is padded to 1 MiB blocks and the manifest to 4 KiB, so the server can't tell how many files there are, what they are called, or their exact sizes.
- **Tamper detection.** Every block is authenticated, and its nonce is tied to its position, so blocks can't be modified, swapped, reordered or truncated without being detected.
- **RAM only, no logs.** Ciphertext is never written to disk. Buffers are zeroed when a share expires, is revoked or self-destructs, or when the server stops. Nothing about requests is logged.
- **Unlisted.** Shares can't be browsed or listed. Each has a random 128‑bit ID, and a missing share and an expired share return the same response.
- **Ephemeral by design.** Shares expire after 5 minutes to 24 hours. They can be revoked at any time or set to self-destruct after the first download.
- **No third parties.** There are no CDNs, web fonts, analytics or cookies, and a strict Content-Security-Policy and `no-referrer` are applied to every response.

### Threat model notes

- Anyone who has the full link can open the share. Send it only to the person who should have it; scanning the QR code is the safest option.
- Over plain `http://`, an *active* attacker on your LAN could tamper with the web page itself before it runs. A passive eavesdropper sees only ciphertext either way. To close that gap, run with HTTPS:

  ```bash
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
    -keyout key.pem -out cert.pem -subj "/CN=locshare"
  ```

  ```bash
  TLS_CERT=cert.pem TLS_KEY=key.pem npm start
  ```

  Browsers will ask you to trust the self-signed certificate once.

## Limits

- Received files are decrypted in browser memory before saving, so very large files (multiple GB) depend on the receiving device's RAM.
- "Save all" produces an uncompressed zip, which is limited to 4 GB in total.
