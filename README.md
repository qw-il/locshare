# LocShare

Private file sharing over your local network. Drop files or write a note on one device, then scan the QR code on another. Your files are encrypted before they leave your device. The machine running LocShare only ever holds scrambled bytes.

## Quick start

```bash
npm install
npm start
```

The server prints addresses such as `http://192.168.1.20:8080`. Open one in a browser on any device on the same Wi‑Fi/LAN.

### HTTPS mode (recommended)

```bash
npm run https
```

This serves LocShare over HTTPS with a certificate the server generates for itself, covering `localhost` and every network address of the machine. No openssl or other setup is needed. The certificate is cached in `.locshare/` so browsers only ask about it once. A new one is made if the machine's addresses change or it nears expiry.

Each device shows a warning the first time, because the certificate isn't from a public authority. Compare the fingerprint the server prints with the one in the browser's certificate details, then choose **Advanced → Proceed**.

HTTPS mode unlocks the following in Chrome and Edge:
- choosing where received files are saved (see below)
- saving folders as real folders
- streaming large files straight to disk

It also stops an attacker on the network from tampering with the page itself.

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | Port to listen on |
| `HOST` | `0.0.0.0` | Interface to bind |
| `MAX_STORE_MB` | `2048` | RAM the host may use to hold shares. Larger shares stream live instead — this is **not** a file size limit |
| `HTTPS` | — | `1` is the same as `npm run https` (self-signed certificate) |
| `TLS_CERT` / `TLS_KEY` | — | Use your own certificate instead |

## Live sessions (paired devices)

Click **Pair a device**, then scan the QR code on a phone, tablet or laptop on the same network. From then on, anything you drop, paste or type on one device appears on the others instantly, in both directions. Up to 8 devices can join a session.

- **How it's protected.** The session key lives only in the QR code or link fragment. Device names, messages and file offers are sealed with that key before they're sent, and the server just relays opaque bytes between connected devices. A device that joins without the key sees nothing it can decrypt and is ignored.
- **How files travel.** Each file streams live from the sender's tab: the other device starts pulling encrypted blocks the moment you drop it, with no upload step and no size limit.
  - Blocks are encrypted on several CPU cores. Over HTTPS that is AES-256-GCM in hardware; over plain HTTP it is XSalsa20-Poly1305.
  - A large copy moves about 16 MB per request, with several requests in flight, so it can fill a gigabit link instead of waiting on one block at a time.
  - Batches up to 256 MB are decrypted automatically on arrival, so saving them is instant. You can also turn on auto-download.
  - Larger batches stream straight to disk when you tap save.
- **When it ends.** Leaving a session, or closing every tab in it, ends it. Any transfers in progress are revoked and wiped.

### Pairing two computers with a code

Computers usually can't scan a QR code, so a session can also show a short code instead. Open **Pair a device**, switch to the **Code** tab, and the code appears (for example `29-816-430`). On the other computer, open the LocShare address, type the code under **Have a pairing code?**, and the two are connected.

- The first number is just a public "slot" that tells the server which pairing is meant. The six digits after it are the secret, and they never leave either computer.
- The computers run [CPace](https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/), a password-authenticated key exchange (PAKE) built on X25519. Both turn the six digits into the same strong key. The session key is then sent across sealed with that key.
- Someone watching or relaying the exchange, including the server, learns nothing they could use to guess the code offline.
- Each code allows exactly one attempt. A wrong guess voids it, the host is told, and a fresh code appears. A guesser therefore has a one-in-a-million chance per code shown.
- Codes expire after 5 minutes. A used slot isn't reissued for 10 minutes, so a stale code can't collide with a new one.

## Choosing where downloads go

Received files and live sessions have a **Save to** setting:

- **Chrome and Edge over HTTPS or `localhost`:**
  - Click **Choose folder** once. From then on, every file and folder you save goes straight into that folder, with no dialog each time. Files never overwrite each other: a repeat save becomes `name (2).ext`.
  - With **Auto-download** on in a live session, received files and folders go there as soon as they arrive.
  - The choice is remembered on that device. Use **Change** to pick another folder, or **×** to go back to asking each time.
  - The browser may ask you to allow access again after a restart.
- **Plain `http://` addresses, Firefox and Safari:** browsers don't let web pages pick a folder here. The setting explains the two options:
  - run `npm run https` and use Chrome or Edge
  - set the browser to ask on every download: Chrome/Edge → *Ask where to save each file*; Firefox → *Always ask you where to save files*; Safari → *File download location → Ask for each download*

The folder you pick is remembered only in that browser, as a local handle in IndexedDB. It is never sent to the server.

## Sharing folders

Drag a folder in, or click **choose a folder**. Subfolders and empty folders are kept. This works for one-off links and in live sessions, and each folder shows as one row that you can expand.

When receiving, **Save folder** or **Save all** writes a real folder to disk with the same structure:

- **Chrome and Edge over HTTPS or `localhost`:** the browser asks where to put it, then streams each file straight into place. If a folder with that name already exists, the new copy is saved as `Name (2)` instead of overwriting it.
- **Other browsers, or plain `http://` on the LAN:** browsers can't write folders here. You get a `.zip` that keeps the folder structure inside it.

To get real folders on plain HTTP, run LocShare with HTTPS (see below).

Folder and file names travel inside the encrypted manifest, so the host never sees them. Paths are sanitised on the receiving side: `..`, absolute paths, drive letters and invalid characters are stripped. A malicious sender therefore can't write outside the folder you choose.

## No file size limit

There are two ways a share can travel. LocShare picks one automatically:

- **Stored.** If the encrypted share fits in the host's memory budget, it is uploaded once. The sender can then close the tab and the recipient downloads whenever they like until it expires.
- **Live.** If the share is bigger than that, it streams directly from the sender's tab. The host relays each encrypted block from the sender's browser to the recipient and never stores it. The sender's tab must stay open until the download finishes. The page warns before closing, and the recipient sees a clear message if the sender has gone.

On the recipient's side, files are decrypted block by block:
- **Chrome and Edge over HTTPS or `localhost`:** decrypted data is written straight to disk via a save dialog, so memory use stays flat whatever the size.
- **Elsewhere:** data is collected in batches into Blobs, which browsers can page to disk.

"Save all" writes a streaming ZIP64 archive, so there is no 4 GB or file-count cap.

## How privacy is protected

- **End-to-end encryption.** Files, file names, types, sizes and notes are encrypted in the browser before they leave the device. A fresh random 256‑bit key is generated for every share. File blocks use AES-256-GCM on HTTPS pages (WebCrypto, hardware accelerated, across several CPU cores). On plain HTTP, where WebCrypto is unavailable, file blocks use XSalsa20‑Poly1305 (NaCl `secretbox`, via [tweetnacl](https://github.com/dchest/tweetnacl-js)), also across several cores. Notes and manifests always use XSalsa20‑Poly1305.
- **The key never reaches the server.** It is placed after the `#` in the link (`/r/<id>#<key>`), and browsers never send that part over the network. When the recipient opens the link, the key is moved into tab-scoped memory and removed from the address bar and browser history.
- **Sizes are hidden.** Data is padded to fixed blocks — 1 MiB for smaller shares, 4 MiB once a share is 32 MiB or larger — and the manifest to 4 KiB, so the server can't tell how many files there are, what they are called, or their exact sizes.
- **Tamper detection.** Every block is authenticated, and its nonce is tied to its position, so blocks can't be modified, swapped, reordered or truncated without being detected.
- **RAM only, no logs.** Ciphertext is never written to disk. Buffers are zeroed when a share expires, is revoked or self-destructs, or when the server stops. Nothing about requests is logged.
- **Unlisted.** Shares can't be browsed or listed. Each has a random 128‑bit ID, and a missing share and an expired share return the same response.
- **Live mode stores nothing.** Oversized shares are relayed block by block and never kept on the host, not even in memory.
- **Ephemeral by design.** Shares expire after 5 minutes to 24 hours. They can be revoked at any time or set to self-destruct after the first download.
- **No third parties.** There are no CDNs, web fonts, analytics or cookies, and a strict Content-Security-Policy and `no-referrer` are applied to every response.

### Threat model notes

- Anyone who has the full link can open the share. Send it only to the person who should have it; scanning the QR code is the safest option.
- Over plain `http://`, an *active* attacker on your LAN could tamper with the web page itself before it runs. A passive eavesdropper sees only ciphertext either way. To close that gap, use `npm run https`. Check the certificate fingerprint the first time, or supply your own certificate with `TLS_CERT` and `TLS_KEY`.

## Tip for very large files

A share bigger than the host's memory (a 180 GB disk image, for example) is not stored. It streams live from the sending tab, and that tab has to stay open until the save finishes.

Run `npm run https` and open the `https://` address in Chrome or Edge on both devices. Encryption then uses AES-256-GCM on several cores, and the browser writes decrypted data straight to disk, so a copy larger than the recipient's RAM still completes. The speed you get is whichever is slower: the network between the two devices, or the disk the file is being written to. Pick a folder under **Save to** beforehand if you want it to land without a dialog.

On plain HTTP the same stream works, but encryption is in JavaScript and will usually be the limit. A spinning hard drive on the receiving side will be the limit even over HTTPS.
