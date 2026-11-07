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
| `MAX_STORE_MB` | `2048` | RAM the host may use to hold shares. Larger shares stream live instead — this is **not** a file size limit |
| `TLS_CERT` / `TLS_KEY` | — | Serve over HTTPS (recommended, see below) |

## Live sessions (paired devices)

Click **Pair a device**, then scan the QR code on a phone, tablet or laptop on the same network. From then on, anything you drop, paste or type on one device appears on the others instantly, in both directions. Up to 8 devices can join a session.

- **How it's protected.** The session key lives only in the QR code or link fragment. Device names, messages and file offers are sealed with that key before they're sent, and the server just relays opaque bytes between connected devices. A device that joins without the key sees nothing it can decrypt and is ignored.
- **How files travel.** Each file streams live from the sender's tab: the other device starts pulling encrypted blocks the moment you drop it, with no upload step and no size limit.
  - Batches up to 256 MB are decrypted automatically on arrival, so saving them is instant. You can also turn on auto-download.
  - Larger batches stream straight to disk when you tap save.
- **When it ends.** Leaving a session, or closing every tab in it, ends it. Any transfers in progress are revoked and wiped.

## No file size limit

There are two ways a share can travel. LocShare picks one automatically:

- **Stored.** If the encrypted share fits in the host's memory budget, it is uploaded once. The sender can then close the tab and the recipient downloads whenever they like until it expires.
- **Live.** If the share is bigger than that, it streams directly from the sender's tab. The host relays each encrypted block from the sender's browser to the recipient and never stores it. The sender's tab must stay open until the download finishes. The page warns before closing, and the recipient sees a clear message if the sender has gone.

On the recipient's side, files are decrypted block by block:
- **Chrome and Edge over HTTPS or `localhost`:** decrypted data is written straight to disk via a save dialog, so memory use stays flat whatever the size.
- **Elsewhere:** data is collected in batches into Blobs, which browsers can page to disk.

"Save all" writes a streaming ZIP64 archive, so there is no 4 GB or file-count cap.

## How privacy is protected

- **End-to-end encryption.** Files, file names, types, sizes and notes are encrypted in the browser with XSalsa20‑Poly1305 (NaCl `secretbox`, via [tweetnacl](https://github.com/dchest/tweetnacl-js)). A fresh random 256‑bit key is generated for every share.
- **The key never reaches the server.** It is placed after the `#` in the link (`/r/<id>#<key>`), and browsers never send that part over the network. When the recipient opens the link, the key is moved into tab-scoped memory and removed from the address bar and browser history.
- **Sizes are hidden.** Data is padded to 1 MiB blocks and the manifest to 4 KiB, so the server can't tell how many files there are, what they are called, or their exact sizes.
- **Tamper detection.** Every block is authenticated, and its nonce is tied to its position, so blocks can't be modified, swapped, reordered or truncated without being detected.
- **RAM only, no logs.** Ciphertext is never written to disk. Buffers are zeroed when a share expires, is revoked or self-destructs, or when the server stops. Nothing about requests is logged.
- **Unlisted.** Shares can't be browsed or listed. Each has a random 128‑bit ID, and a missing share and an expired share return the same response.
- **Live mode stores nothing.** Oversized shares are relayed block by block and never kept on the host, not even in memory.
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

## Tip for very large files

Run LocShare with HTTPS (see above) and receive in Chrome or Edge. The browser then streams decrypted data straight to disk, so even a file larger than the recipient's RAM saves smoothly.
