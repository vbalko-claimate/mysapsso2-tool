# MYSAPSSO2 Token Tool

Web-based tool for decoding and encoding SAP MYSAPSSO2 Single Sign-On logon tickets. Parses TLV fields, handles PKCS#7/CMS signature blocks (including SAP's BER indefinite-length encoding), and supports optional token signing with PEM keys.

**Live demo:** [mysapsso2.app.claimate.tech](https://mysapsso2.app.claimate.tech)

## Features

- **Decode** — paste a base64-encoded MYSAPSSO2 cookie and instantly see all fields (user, issuer system ID, issuer client, creation time, signature flags, etc.) with raw hex
- **Encode** — build tokens from field values, optionally sign with a PEM private key and certificate (SHA-1 digest, detached, no authenticatedAttributes — the combination verified against S/4HANA with CommonCryptoLib 8.x)
- **PKCS#7 signature parsing** — extracts issuer CN, serial number, digest algorithm, certificate signature algorithm, and signing time from SAP's BER-encoded CMS signatures
- **SAP acceptance warnings** — the decoder flags conditions that make SAP reject the ticket at verification time: SHA-256-signed certificates (`SsfVerify returned 5`), non-SHA-1 digests, authenticatedAttributes with RSA, and future creation timestamps (`HMskiCheckValidity failed`)
- **Load Example** — one-click demo token generation for quick exploration
- **Round-trip verification** — encode a token, then click "Decode This" to verify it
- **Copy JSON** — export full decoded results to clipboard
- **Datetime picker** — creation-time field auto-formats to SAP's `YYYYMMDDHHmmss` UTC format
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
    "issuerCN": "my-btp-token-issuer",
    "serial": "673a2e932e331f30",
    "digestAlgorithm": "sha1",
    "certSignatureAlgorithm": "sha1WithRSAEncryption",
    "parsed": true,
    "length": 544
  },
  "warnings": []
}
```

`warnings` lists conditions that make SAP reject the ticket even though it decodes fine (wrong certificate signature algorithm, non-SHA-1 digest, authenticatedAttributes with RSA, future creation timestamp).

### `POST /api/encode`

Encode a new MYSAPSSO2 token.

**Request:**

```json
{
  "user": "SAPUSER",
  "sysId": "PRD",
  "client": "100",
  "creationTime": "20260603120000",
  "pemKey": "-----BEGIN RSA PRIVATE KEY-----\n...",
  "pemCert": "-----BEGIN CERTIFICATE-----\n..."
}
```

- `sysId` / `client` identify the **issuer** of the token (your application), not the target SAP system. They must match the ACL entry in the target's `STRUSTSSO2`.
- `creationTime` is the token **creation** timestamp (UTC, `YYYYMMDDHHmmss`), defaulting to now. It is *not* an expiry — SAP computes expiration as creation time + `login/ticket_expiration_time` and rejects future creation dates. (`validity` is accepted as a deprecated alias.)
- `pemKey` and `pemCert` are optional. Without them, the token is unsigned. The certificate must be **SHA-1-signed** for SAP to verify the ticket; tokens are signed with SHA-1 digest, detached, without authenticatedAttributes.

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
| `0x02` | System ID (**issuer**, not target) | UTF-16LE |
| `0x03` | Client (**issuer**, not target) | UTF-16LE |
| `0x04` | Creation time (**not** expiry — SAP adds its own validity period) | UTF-16LE `YYYYMMDDHHmmss` UTC |
| `0x05` | Signature Flags | Raw bytes |
| `0x06` | Recipient Info | UTF-16LE |
| `0x09` | Short Info | UTF-16LE |

## SAP Acceptance Requirements

Decoding a token tells you what's inside it; getting SAP to *accept* it is another story. These requirements were verified against a production S/4HANA (kernel 7.93, CommonCryptoLib 8.5.x) — all of them fail silently at import time and only surface in kernel traces:

- **SHA-1-signed certificate** — `openssl req -sha1 …`. A `sha256WithRSAEncryption` certificate imports into `STRUSTSSO2` without error but fails verification (`SsfVerify returned 5`).
- **SHA-1 digest, no authenticatedAttributes, detached signature** — with RSA keys, CommonCryptoLib cannot verify PKCS#7 signatures computed over authenticated attributes. DSA 1024 + SHA-1 works on all NetWeaver versions; RSA 2048 + SHA-1 works on CommonCryptoLib 8.x.
- **Creation time in field 4** — a future timestamp is rejected (`invalid format: ticket creation date` / `HMskiCheckValidity failed`).
- **`login/accept_sso2_ticket = 1`** on the accepting system (`RZ11`).
- **`STRUSTSSO2` is client-dependent** — certificate into the Certificate List in client 000, ACL entry (issuer System ID + Client) in the client users log into. ACL table: `TWPSSO2ACL`.
- **ICM soft restart** after `STRUSTSSO2` changes (`SMICM`, SAP Note 510007).

The tool's decoder warns about the first three automatically.

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
