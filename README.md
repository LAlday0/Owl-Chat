# Owl Chat

A real-time chat application with end-to-end encrypted messages. The server relays and
stores ciphertext only and never holds the key.

## Running

```
npm install
npm start          # http://localhost:3000
npm test           # known-answer tests + end-to-end socket test
npm run bench      # our AES-128-CBC vs. the built-in Web Crypto implementation
```

Open two browser tabs, pick a username in each and type the **same shared secret** in both,
then press *Join*. Tick *show ciphertext* to see what actually travels over the socket.

## Layout

| File | Purpose |
| --- | --- |
| `index.js` | Node.js + Socket.IO server; stores `{ username, iv, ciphertext }` in SQLite |
| `index.html` | Chat page |
| `public/aes.js` | AES-128 from scratch (key expansion, SubBytes/ShiftRows/MixColumns/AddRoundKey and inverses), CBC mode, PKCS#7 padding |
| `public/chat.js` | Client: encrypts before emitting, decrypts after receiving |
| `test/aes.test.js` | FIPS 197 / NIST SP 800-38A known-answer tests, OpenSSL cross-check |
| `test/chat.test.js` | Two clients exchanging an encrypted message through a real server |

Environment variables: `PORT` (default 3000), `OWLCHAT_DB` (default `owlchat.db`).

## How a message is protected

1. The key is `SHA-256(shared secret)` truncated to 128 bits, computed in the browser
   with the Web Crypto API (`crypto.subtle.digest`). AES is the only primitive this
   project implements itself.
2. The plaintext is UTF-8 encoded and padded with PKCS#7.
3. It is encrypted with AES-128 in CBC mode using a **fresh random IV per message**.
4. `{ iv, ciphertext }` are base64 encoded and emitted over the socket; the server inserts
   them into SQLite and broadcasts them unchanged.
5. The receiving client decrypts with the same key and the IV that came with the message.

## Limitations

- The shared secret is still typed in by hand; the Diffie-Hellman exchange that replaces
  this step is the next piece of the project.
- Written for learning: not hardened against side-channel (timing) attacks.
- `crypto.subtle` only exists in a secure context, so the page must be served over
  `https://` or from `localhost`; joining from a plain `http://` LAN address fails.
- A single unsalted `SHA-256` is a weak KDF for a hand-typed secret. It is adequate for
  a high-entropy Diffie-Hellman secret, which is where this step is heading.
- CBC provides confidentiality but no integrity - tampering is not detected. A MAC
  (encrypt-then-MAC) would be needed for that.
- Our implementation is roughly two orders of magnitude slower than Web Crypto
  (see `npm run bench`), which is still negligible for chat-sized messages.
