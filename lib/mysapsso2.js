const forge = require('node-forge');

/**
 * MYSAPSSO2 Token Field IDs
 */
const FIELD_IDS = {
  1: 'user',
  2: 'sysId',
  3: 'client',
  4: 'validity',
  5: 'signatureFlags',
  6: 'recipientInfo',
  9: 'shortInfo',
};

const FIELD_LABELS = {
  user: 'User',
  sysId: 'System ID',
  client: 'Client',
  validity: 'Validity Timestamp',
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

  return result;
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
    }

    if (p7.signers && p7.signers.length > 0) {
      const signer = p7.signers[0];
      info.digestAlgorithm = forge.pki.oids[signer.digestAlgorithm] || signer.digestAlgorithm;
      info.signatureAlgorithm = forge.pki.oids[signer.signatureAlgorithm] || signer.signatureAlgorithm;
      if (signer.authenticatedAttributes) {
        for (const attr of signer.authenticatedAttributes) {
          if (attr.type === forge.pki.oids.signingTime || attr.type === '1.2.840.113549.1.9.5') {
            info.signingTime = attr.value;
          }
        }
      }
    }

    // Fallback: extract from rawCapture (SAP uses BER indefinite-length
    // encoding which the high-level API can't fully resolve)
    const rc = p7.rawCapture;
    if (rc && !info.serial) {
      // Serial number
      if (rc.serial) {
        info.serial = Buffer.from(rc.serial, 'binary').toString('hex');
      }

      // Issuer DN — rawCapture.issuer is already a parsed ASN.1 object
      if (rc.issuer) {
        try {
          const issuerAttrs = forge.pki.RDNAttributesAsArray(rc.issuer);
          const cn = issuerAttrs.find(a => a.shortName === 'CN');
          if (cn) info.issuerCN = cn.value;
        } catch (_) {}
      }

      // Digest algorithm
      if (rc.digestAlgorithm) {
        const oidBytes = typeof rc.digestAlgorithm === 'string'
          ? rc.digestAlgorithm
          : rc.digestAlgorithm.value || '';
        const oid = forge.asn1.derToOid(oidBytes);
        info.digestAlgorithm = forge.pki.oids[oid] || oid;
      }

      // Authenticated attributes — look for signing time
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
 * @param {object} params
 * @param {string} params.user
 * @param {string} params.sysId
 * @param {string} params.client
 * @param {string} [params.validity] — timestamp string
 * @param {string} [params.pemKey] — PEM private key for signing
 * @param {string} [params.pemCert] — PEM certificate for signing
 * @returns {string} base64-encoded token
 */
function encode(params) {
  const { user, sysId, client, validity } = params;
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
  addTextField(2, sysId);
  addTextField(3, client);
  if (validity) {
    addTextField(4, validity);
  }

  // Signature flags (dummy: 4 zero bytes)
  const sigFlagsHeader = Buffer.alloc(3);
  sigFlagsHeader[0] = 5;
  sigFlagsHeader.writeUInt16BE(4, 1);
  parts.push(sigFlagsHeader);
  parts.push(Buffer.from([0x00, 0x00, 0x00, 0x00]));

  // 0xFF marker
  parts.push(Buffer.from([0xff]));

  // Build the data payload (everything before 0xFF) for signing
  const dataPayload = Buffer.concat(parts);

  // Sign if key and cert are provided
  if (params.pemKey && params.pemCert) {
    try {
      const privateKey = forge.pki.privateKeyFromPem(params.pemKey);
      const cert = forge.pki.certificateFromPem(params.pemCert);

      const p7 = forge.pkcs7.createSignedData();
      p7.content = forge.util.createBuffer(dataPayload);
      p7.addCertificate(cert);
      p7.addSigner({
        key: privateKey,
        certificate: cert,
        digestAlgorithm: forge.pki.oids.sha256,
        authenticatedAttributes: [
          { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
          { type: forge.pki.oids.messageDigest },
          { type: forge.pki.oids.signingTime, value: new Date() },
        ],
      });
      p7.sign();

      const asn1 = p7.toAsn1();
      const derBytes = forge.asn1.toDer(asn1);
      const sigBuffer = Buffer.from(derBytes.getBytes(), 'binary');
      parts.push(sigBuffer);
    } catch (e) {
      throw new Error(`Signing failed: ${e.message}`);
    }
  } else {
    // No signing — append an empty placeholder so the token is still structurally valid
    // (unsigned tokens won't be accepted by SAP but are useful for testing)
  }

  const token = Buffer.concat(parts);
  return token.toString('base64');
}

module.exports = { decode, encode, FIELD_IDS, FIELD_LABELS };
