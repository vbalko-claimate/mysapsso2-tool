# MYSAPSSO2 Token Tool

Web-based tool for decoding and encoding SAP MYSAPSSO2 Single Sign-On logon tickets. Parses TLV fields, handles PKCS#7/CMS signature blocks (including SAP's BER indefinite-length encoding), and supports optional token signing with PEM keys.

**Live demo:** [mysapsso2.app.claimate.tech](https://mysapsso2.app.claimate.tech)

## Features

- **Decode** — paste a base64-encoded MYSAPSSO2 cookie and instantly see all fields (user, system ID, client, validity, signature flags, etc.) with raw hex
- **Encode** — build tokens from field values, optionally sign with a PEM private key and certificate
- **PKCS#7 signature parsing** — extracts issuer CN, serial number, digest algorithm, and signing time from SAP's BER-encoded CMS signatures
- **Load Example** — one-click demo token generation for quick exploration
- **Round-trip verification** — encode a token, then click "Decode This" to verify it
- **Copy JSON** — export full decoded results to clipboard
- **Datetime picker** — validity field auto-formats to SAP's `YYYYMMDDHHmmss` format
- **Keyboard shortcut** — `Ctrl/Cmd+Enter` to submit the active form
- **Help tab** — built-in documentation covering token structure, TLV field reference, and usage guidance
- **Docker ready** — multi-stage Dockerfile with health checks

## Quick Start

### Node.js

```bash
npm install
npm start
```

Open [http://localhost:3000](http://localhost:3000).

### Docker

```bash
docker compose up -d
```

### Docker (manual build)

```bash
docker build -t mysapsso2-tool .
docker run -p 3000:3000 mysapsso2-tool
```

## API

### `POST /api/decode`

Decode a base64 MYSAPSSO2 token.

**Request:**

```json
{
  "token": "AjQxMDMBABpEAEUATQBP..."
}
```

**Response:**

```json
{
  "version": 2,
  "codepage": "4103",
  "fields": [
    {
      "id": 1,
      "name": "user",
      "label": "User",
      "length": 26,
      "value": "michael.davis",
      "hex": "6d00690063006800..."
    }
  ],
  "signature": {
    "issuerCN": "Prometheus Group Auth Service",
    "serial": "673a2e932e331f30",
    "digestAlgorithm": "sha1",
    "signingTime": "260209164214Z",
    "parsed": true,
    "length": 544
  }
}
```

### `POST /api/encode`

Encode a new MYSAPSSO2 token.

**Request:**

```json
{
  "user": "SAPUSER",
  "sysId": "PRD",
  "client": "100",
  "validity": "20261231235959",
  "pemKey": "-----BEGIN RSA PRIVATE KEY-----\n...",
  "pemCert": "-----BEGIN CERTIFICATE-----\n..."
}
```

`pemKey` and `pemCert` are optional. Without them, the token is unsigned.

**Response:**

```json
{
  "token": "AjQxMDMBABBTAEEA..."
}
```

### `GET /api/health`

Returns `{ "status": "ok" }`.

## Token Structure

MYSAPSSO2 tokens are base64-encoded binary blobs:

| Offset | Content |
|--------|---------|
| 0 | Version byte (usually `0x02`) |
| 1–4 | Codepage — 4 ASCII bytes (e.g. `4103`) |
| 5…n | TLV fields (1-byte tag, 2-byte BE length, value) |
| n+1 | `0xFF` end-of-fields marker |
| n+2…n+3 | Signature length — 2-byte big-endian uint16 |
| n+4… | PKCS#7 / CMS signature block (BER/DER) |

### TLV Field IDs

| ID | Name | Encoding |
|----|------|----------|
| `0x01` | User | UTF-16LE |
| `0x02` | System ID | UTF-16LE |
| `0x03` | Client | UTF-16LE |
| `0x04` | Validity (expiry) | UTF-16LE `YYYYMMDDHHmmss` |
| `0x05` | Signature Flags | Raw bytes |
| `0x06` | Recipient Info | UTF-16LE |
| `0x09` | Short Info | UTF-16LE |

## Tech Stack

- **Runtime:** Node.js 20
- **Server:** Express 4
- **Crypto:** node-forge (ASN.1/DER parsing, PKCS#7, PKI)
- **Frontend:** Vanilla HTML/JS + Tailwind CSS (CDN)
- **Container:** Alpine-based multi-stage Docker build

## Security Notes

- **Unsigned tokens** will not be accepted by production SAP systems — they require a valid PKCS#7 signature from a trusted certificate.
- When signing, the **private key is sent to the server**. Only run this tool in trusted environments (localhost, internal network).
- This tool is intended for **development, testing, and educational purposes**.
- Never use production private keys on untrusted servers.

## License

MIT

---

Created by vladimir.balko at [claimate.tech](https://www.claimate.tech)
