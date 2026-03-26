# Ed25519 Signed Envelope Protocol — Demo

An interactive full-stack demonstration of the **Ed25519 Signed Envelope Protocol**, featuring a React frontend with live cryptographic operations

---

## What it does

- Generates an Ed25519 key pair in the browser on load
- Signs an arbitrary JSON payload into a **signed envelope** (base64 payload + signature + timestamp)
- Verifies the envelope against the public key and displays the recovered payload
- Lets you **tamper** the envelope to see the signature check fail in real time
- Emits metrics for every operation: sign/verify time, payload size, signature size, key strength, and security level

---

## Project structure

```
.
├── index.html                  # Vite HTML entry point
├── package.json                # npm manifest (React 18 + Vite 5)
├── vite.config.js              # Vite config with module resolution aliases
└── src/
    ├── main.jsx                # React DOM mount
    └── Ed25519Demo.jsx         # Main React component
```

---

## Getting started

### 1. Create `src/main.jsx`

```jsx
import React from "react";
import ReactDOM from "react-dom/client";
import Ed25519Demo from "./Ed25519Demo";

ReactDOM.createRoot(document.getElementById("root")).render(<Ed25519Demo />);
```

### 2. Install and run the frontend

```bash
npm install
npm run dev
```

Open [http://localhost:5173](http://localhost:5173).

---

## How the signed envelope works

```
Payload (JSON)
    │
    ▼
Canonicalize ── sort keys, strip whitespace ──► canonical bytes
    │
    ▼
Sign ── EdDSA(privateKey, canonical bytes) ──► 64-byte signature
    │
    ▼
Wrap ── base64(canonical) + base64(signature) + algorithm + timestamp
    │
    ▼
Signed Envelope  ◄──── transmit ────►  Verify
                                            │
                                     decode base64
                                            │
                                     EdDSA verify(pubKey, sig, bytes)
                                            │
                                   valid ──► parse JSON
                                  invalid ──► raise error
```

---

## Protocol properties

| Property | Value |
|----------|-------|
| Curve | Curve25519 (twisted Edwards form) |
| Signature scheme | EdDSA (RFC 8032) |
| Hash function | SHA-512 (internal to Ed25519) |
| Key size | 256 bits |
| Signature size | 64 bytes (fixed) |
| Security level | 128-bit (equivalent to AES-128) |
| Deterministic | Yes — no random nonce required |
| Quantum safe | No — vulnerable to Shor's algorithm |
| Attack complexity | 2¹²⁸ operations (best known ECDLP) |

---

## Browser note

The Web Crypto API's Ed25519 support (`Ed25519` named curve) is a draft proposal and not yet universally available. The React frontend uses **ECDSA P-256 + SHA-256** as a drop-in simulation. The protocol structure (canonicalization, envelope format, metrics) is identical to the real Ed25519 flow
---

## Dependencies

**Frontend**
- `react` 18
- `react-dom` 18
- `vite` 5
- `@vitejs/plugin-react` 4

## License

MIT