const forge = require('node-forge');

/**
 * MYSAPSSO2 Token Field IDs
 */
const FIELD_IDS = {
  1: 'user',
  2: 'sysId',
  3: 'client',
  4: 'creationTime',
  5: 'signatureFlags',
  6: 'recipientInfo',
  9: 'shortInfo',
};

// Note: field 4 is the ticket CREATION time, not an expiry. SAP computes the
// expiration itself as creation time + login/ticket_expiration_time on the
// accepting system. Fields 2/3 identify the ISSUER system/client, not the
// target system.
const FIELD_LABELS = {
  user: 'User',
  sysId: 'System ID (Issuer)',
  client: 'Client (Issuer)',
  creationTime: 'Creation Time (UTC)',
  signatureFlags: 'Signature Flags',
  recipientInfo: 'Recipient Info',
  shortInfo: 'Short Info',
};

/**
 * Decode a MYSAPSSO2 token from base64 string.
 */
function decode(base64Token) {
  const raw = Buffer.from(base64Token.replace(/\s/g, ''), 'base64');
  let offset = 0;
  const result = { fields: [], signature: null, raw: { hex: raw.toString('hex') } };

  // Version byte
  if (raw.length < 1) throw new Error('Token too short');
  const version = raw[offset++];
  result.version = version;

  // Codepage — 4 ASCII bytes representing e.g. "4103"
  if (offset + 4 > raw.length) throw new Error('Token too short for codepage');
  const codepage = raw.slice(offset, offset + 4).toString('ascii');
  offset += 4;
  result.codepage = codepage;

  // Parse TLV fields until we hit 0xFF marker or run out of data
  while (offset < raw.length) {
    if (raw[offset] === 0xff) {
      offset++; // skip the marker
      break;
    }

    if (offset + 3 > raw.length) break;

    const fieldId = raw[offset++];
    const fieldLen = raw.readUInt16BE(offset);
    offset += 2;

    if (offset + fieldLen > raw.length) {
      throw new Error(`Field ${fieldId} extends beyond token (offset=${offset}, len=${fieldLen}, total=${raw.length})`);
    }

    const fieldValue = raw.slice(offset, offset + fieldLen);
    offset += fieldLen;

    const fieldName = FIELD_IDS[fieldId] || `unknown_${fieldId}`;
    const label = FIELD_LABELS[fieldName] || fieldName;

    let decoded;
    if (fieldId === 5) {
      // Signature flags — 4 raw bytes
      decoded = fieldValue.toString('hex');
    } else {
      // UTF-16LE text fields
      decoded = fieldValue.toString('utf16le');
    }

    result.fields.push({
      id: fieldId,
      name: fieldName,
      label,
      length: fieldLen,
      value: decoded,
      hex: fieldValue.toString('hex'),
    });
  }

  // Remaining bytes after 0xFF marker are the PKCS#7 signature
  // Format: 2-byte big-endian length prefix, then the DER-encoded PKCS#7 data
  if (offset + 2 < raw.length) {
    const sigLen = raw.readUInt16BE(offset);
    offset += 2;
    const sigBytes = raw.slice(offset, offset + sigLen);
    result.signature = parseSignature(sigBytes);
    result.signatureHex = sigBytes.toString('hex');
  }

  result.warnings = collectWarnings(result);

  return result;
}

/**
 * SAP-acceptance heuristics learned from real S/4HANA deployments
 * (kernel 7.93, CommonCryptoLib 8.5.x). These conditions all import/decode
 * fine but cause the ticket to be rejected at verification time.
 */
function collectWarnings(result) {
  const warnings = [];

  // Field 4 is the ticket CREATION date. A future timestamp is rejected by
  // SAP with "invalid format: ticket creation date" / "HMskiCheckValidity failed".
  const ct = result.fields.find((f) => f.id === 4);
  if (ct && /^\d{14}$/.test(ct.value)) {
    const iso = `${ct.value.slice(0, 4)}-${ct.value.slice(4, 6)}-${ct.value.slice(6, 8)}T` +
      `${ct.value.slice(8, 10)}:${ct.value.slice(10, 12)}:${ct.value.slice(12, 14)}Z`;
    const created = Date.parse(iso);
    if (!Number.isNaN(created) && created > Date.now() + 5 * 60 * 1000) {
      warnings.push('Creation time (field 4) is in the future. SAP reads this field as the ticket CREATION date and rejects future values ("HMskiCheckValidity failed"). Use the current time — SAP adds its own validity period (login/ticket_expiration_time).');
    }
  }

  const sig = result.signature;
  if (sig && sig.parsed) {
    if (sig.certSignatureAlgorithm && !/sha-?1/i.test(String(sig.certSignatureAlgorithm))) {
      warnings.push(`Signing certificate is ${sig.certSignatureAlgorithm}. SAP CommonCryptoLib imports such certificates into STRUSTSSO2 without error but fails verification ("SsfVerify returned 5"). The certificate must be SHA-1-signed (e.g. sha1WithRSAEncryption — openssl req -sha1).`);
    }
    if (sig.digestAlgorithm && !/sha-?1/i.test(String(sig.digestAlgorithm))) {
      warnings.push(`PKCS#7 digest algorithm is ${sig.digestAlgorithm}. SAP expects SHA-1 (trace shows "Alg=SHA1").`);
    }
    if (sig.hasAuthenticatedAttributes) {
      warnings.push('PKCS#7 signature contains authenticatedAttributes. With RSA keys, CommonCryptoLib fails to verify such signatures ("SSF_API_SIGNER_ERRORS") — sign without authenticatedAttributes. (DSA keys tolerate them.)');
    }
  }

  return warnings;
}

/**
 * Parse the PKCS#7/CMS signature block using node-forge.
 */
function parseSignature(sigBytes) {
  try {
    const derBuffer = forge.util.createBuffer(sigBytes);
    const asn1 = forge.asn1.fromDer(derBuffer, { parseAllBytes: false, strict: false });
    const p7 = forge.pkcs7.messageFromAsn1(asn1);

    const info = {};

    // Try high-level API first (works for definite-length DER)
    if (p7.certificates && p7.certificates.length > 0) {
      const cert = p7.certificates[0];
      info.issuerCN = cert.issuer.getField('CN')?.value || '';
      info.subjectCN = cert.subject.getField('CN')?.value || '';
      info.serial = cert.serialNumber;
      info.notBefore = cert.validity.notBefore?.toISOString();
      info.notAfter = cert.validity.notAfter?.toISOString();
      // The certificate's own signature algorithm — must be SHA-1-based for
      // SAP CommonCryptoLib to verify the ticket (see collectWarnings)
      info.certSignatureAlgorithm = forge.pki.oids[cert.signatureOid] || cert.signatureOid;
    }

    if (p7.signers && p7.signers.length > 0) {
      const signer = p7.signers[0];
      info.digestAlgorithm = forge.pki.oids[signer.digestAlgorithm] || signer.digestAlgorithm;
      info.signatureAlgorithm = forge.pki.oids[signer.signatureAlgorithm] || signer.signatureAlgorithm;
      if (signer.authenticatedAttributes && signer.authenticatedAttributes.length > 0) {
        info.hasAuthenticatedAttributes = true;
      }
      if (signer.authenticatedAttributes) {
        for (const attr of signer.authenticatedAttributes) {
          if (attr.type === forge.pki.oids.signingTime || attr.type === '1.2.840.113549.1.9.5') {
            info.signingTime = attr.value;
          }
        }
      }
    }

    // Fallback: extract from rawCapture (SAP uses BER indefinite-length
    // encoding which the high-level API can't fully resolve). Fill each
    // field individually — the high-level API may resolve some but not all.
    const rc = p7.rawCapture;
    if (rc) {
      // Serial number
      if (rc.serial && !info.serial) {
        info.serial = Buffer.from(rc.serial, 'binary').toString('hex');
      }

      // Issuer DN — rawCapture.issuer is already a parsed ASN.1 object
      if (rc.issuer && !info.issuerCN) {
        try {
          const issuerAttrs = forge.pki.RDNAttributesAsArray(rc.issuer);
          const cn = issuerAttrs.find(a => a.shortName === 'CN');
          if (cn) info.issuerCN = cn.value;
        } catch (_) {}
      }

      // Digest algorithm
      if (rc.digestAlgorithm && !info.digestAlgorithm) {
        const oidBytes = typeof rc.digestAlgorithm === 'string'
          ? rc.digestAlgorithm
          : rc.digestAlgorithm.value || '';
        const oid = forge.asn1.derToOid(oidBytes);
        info.digestAlgorithm = forge.pki.oids[oid] || oid;
      }

      // Authenticated attributes — look for signing time
      if (rc.authenticatedAttributes && Array.isArray(rc.authenticatedAttributes) && rc.authenticatedAttributes.length > 0) {
        info.hasAuthenticatedAttributes = true;
      }
      if (rc.authenticatedAttributes && Array.isArray(rc.authenticatedAttributes)) {
        for (const attrAsn1 of rc.authenticatedAttributes) {
          try {
            const seq = Array.isArray(attrAsn1.value) ? attrAsn1 : forge.asn1.fromDer(
              forge.util.createBuffer(Buffer.from(attrAsn1, 'binary')),
              { parseAllBytes: false, strict: false });
            if (Array.isArray(seq.value) && seq.value.length >= 2) {
              const oid = forge.asn1.derToOid(seq.value[0].value);
              if (oid === '1.2.840.113549.1.9.5') {
                // signingTime — value is a SET containing a UTCTime or GeneralizedTime
                const timeSet = seq.value[1];
                const timeVal = Array.isArray(timeSet.value) ? timeSet.value[0] : timeSet;
                info.signingTime = timeVal.value;
              }
            }
          } catch (_) {}
        }
      }
    }

    info.parsed = true;
    info.length = sigBytes.length;
    return info;
  } catch (e) {
    return { parsed: false, error: e.message, length: sigBytes.length };
  }
}

/**
 * Encode a MYSAPSSO2 token.
 *
 * The signing parameters (SHA-1 digest, detached signature, NO
 * authenticatedAttributes) are verified against a production S/4HANA
 * (kernel 7.93, CommonCryptoLib 8.5.x). SHA-256 digests and
 * authenticatedAttributes both make SsfVerify fail with RSA keys.
 *
 * @param {object} params
 * @param {string} params.user
 * @param {string} params.sysId — ISSUER system ID (identifies the token issuer, not the target SAP system)
 * @param {string} params.client — ISSUER client
 * @param {string} [params.creationTime] — token creation timestamp (UTC, YYYYMMDDHHmmss).
 *   Defaults to now. This is NOT an expiry — SAP computes the expiration itself
 *   as creation time + login/ticket_expiration_time. A future value is rejected.
 * @param {string} [params.validity] — deprecated alias for creationTime
 * @param {string} [params.pemKey] — PEM private key for signing
 * @param {string} [params.pemCert] — PEM certificate for signing (must be SHA-1-signed for SAP)
 * @returns {string} base64-encoded token
 */
function encode(params) {
  const { user, sysId, client } = params;
  const creationTime = params.creationTime || params.validity ||
    new Date().toISOString().replace(/[-T:.Z]/g, '').substring(0, 14);
  const parts = [];

  // Version
  parts.push(Buffer.from([0x02]));

  // Codepage
  parts.push(Buffer.from('4103', 'ascii'));

  // TLV fields
  function addTextField(id, value) {
    if (!value) return;
    const textBuf = Buffer.from(value, 'utf16le');
    const header = Buffer.alloc(3);
    header[0] = id;
    header.writeUInt16BE(textBuf.length, 1);
    parts.push(header);
    parts.push(textBuf);
  }

  addTextField(1, user);
  addTextField(2, sysId);        // issuer system ID
  addTextField(3, client);       // issuer client
  addTextField(4, creationTime); // creation timestamp (SAP adds its own validity period)

  // Signature flags (dummy: 4 zero bytes)
  const sigFlagsHeader = Buffer.alloc(3);
  sigFlagsHeader[0] = 5;
  sigFlagsHeader.writeUInt16BE(4, 1);
  parts.push(sigFlagsHeader);
  parts.push(Buffer.from([0x00, 0x00, 0x00, 0x00]));

  // Data payload to sign — everything BEFORE the 0xFF marker
  const dataPayload = Buffer.concat(parts);

  const out = [dataPayload, Buffer.from([0xff])];

  // Sign if key and cert are provided
  if (params.pemKey && params.pemCert) {
    try {
      const privateKey = forge.pki.privateKeyFromPem(params.pemKey);
      const cert = forge.pki.certificateFromPem(params.pemCert);

      const p7 = forge.pkcs7.createSignedData();
      p7.content = forge.util.createBuffer(dataPayload.toString('binary'));
      p7.addCertificate(cert);
      p7.addSigner({
        key: privateKey,
        certificate: cert,
        digestAlgorithm: forge.pki.oids.sha1,
        // NO authenticatedAttributes — RSA + CommonCryptoLib requires their absence
      });
      p7.sign({ detached: true });

      const sigBuffer = Buffer.from(forge.asn1.toDer(p7.toAsn1()).getBytes(), 'binary');
      const sigLenBuf = Buffer.alloc(2);
      sigLenBuf.writeUInt16BE(sigBuffer.length, 0);
      out.push(sigLenBuf, sigBuffer);
    } catch (e) {
      throw new Error(`Signing failed: ${e.message}`);
    }
  }
  // Without key/cert the token stays unsigned — structurally valid for testing,
  // but SAP systems will not accept it.

  return Buffer.concat(out).toString('base64');
}

module.exports = { decode, encode, FIELD_IDS, FIELD_LABELS };
