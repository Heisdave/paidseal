// PaidSeal core Tari cryptography, mirrored from Tari source (v6.3.0-pre.4 / tari_crypto 0.24.1).
// Pure functions, no I/O. Works in Node and the browser.
// Sources:
//  - DomainSeparatedHasher: tari-crypto src/hashing.rs (tag = "{domain}.v{version}[.{label}]",
//    each item length-prefixed with u64 LE, tag itself length-prefixed the same way)
//  - AEAD KDF: transaction_components encrypted_data.rs kdf_aead()
//  - EncryptedData: XChaCha20-Poly1305, layout tag(16) || nonce(24) || ciphertext,
//    plaintext = value u64 LE || mask 32 || memo bytes, AAD below
//  - CheckSig Schnorr: tari_script CheckSigSchnorrSignature = SchnorrSignature<CheckSigHashDomain>,
//    challenge = domain hash label "challenge" over (R, P, message), wide reduction, s*G == R + e*P
//  - Pedersen: C = mask*G + value*H over Ristretto255

import { ed25519, RistrettoPoint } from '@noble/curves/ed25519';
import { blake2b } from '@noble/hashes/blake2b';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { sha256 } from '@noble/hashes/sha256';

const L = ed25519.CURVE.n; // group order

export const PEDERSEN_H_HEX = 'ce389841c0c8698ab95b70242aeea64840b1eac5f644b7d008ac0587cf471d70';
export const ENCRYPTED_DATA_AAD = new TextEncoder().encode('TARI_AAD_VALUE_AND_MASK_EXTEND_NONCE_VARIANT');

export function hexToBytes(hex) {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  return out;
}
export function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}
export function leBytesToBigInt(bytes) {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
  return n;
}
export function bigIntToLeBytes(n, len = 32) {
  const out = new Uint8Array(len);
  let v = n;
  for (let i = 0; i < len; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}
// Tari PrivateKey::from_uniform_bytes: wide reduction of 64 bytes mod l
export function scalarFromUniformBytes(bytes64) {
  return leBytesToBigInt(bytes64) % L;
}
export function scalarFromCanonicalBytes(bytes32) {
  const n = leBytesToBigInt(bytes32);
  if (n >= L) throw new Error('non-canonical scalar');
  return n;
}

function u64le(n) {
  const out = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 0; i < 8; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}
function concat(...parts) {
  const total = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

// DomainSeparatedHasher from tari_crypto hashing.rs
export function domainSeparatedHash(domain, version, label, items, outLen) {
  const tag = label ? `${domain}.v${version}.${label}` : `${domain}.v${version}`;
  const tagBytes = new TextEncoder().encode(tag);
  const parts = [u64le(tagBytes.length), tagBytes];
  for (const item of items) {
    parts.push(u64le(item.length), item);
  }
  return blake2b(concat(...parts), { dkLen: outLen });
}

function mul(point, scalar) {
  const s = ((scalar % L) + L) % L;
  return s === 0n ? RistrettoPoint.ZERO : point.multiply(s);
}

// ---- Pedersen commitment check: C == mask*G + value*H ----
export function verifyCommitmentOpening(commitmentHex, maskHex, valueMicroTari) {
  const C = RistrettoPoint.fromHex(hexToBytes(commitmentHex));
  const H = RistrettoPoint.fromHex(hexToBytes(PEDERSEN_H_HEX));
  const mask = scalarFromCanonicalBytes(hexToBytes(maskHex));
  const value = BigInt(valueMicroTari) % L;
  const computed = mul(RistrettoPoint.BASE, mask).add(mul(H, value));
  return computed.equals(C);
}

// ---- Tari Schnorr verification (generic over the hash domain) ----
// message is the exact byte string that was signed. Signature is R || s.
export function verifySchnorr(domain, version, pubKeyHex, messageBytes, signatureHex) {
  const sig = hexToBytes(signatureHex);
  if (sig.length !== 64) throw new Error(`signature must be 64 bytes, got ${sig.length}`);
  const rBytes = sig.slice(0, 32);
  const sBytes = sig.slice(32, 64);
  const R = RistrettoPoint.fromHex(rBytes);
  const P = RistrettoPoint.fromHex(hexToBytes(pubKeyHex));
  if (P.equals(RistrettoPoint.ZERO)) return false;
  const s = scalarFromCanonicalBytes(sBytes);
  const challenge = domainSeparatedHash(
    domain, version, 'challenge',
    [rBytes, hexToBytes(pubKeyHex), messageBytes], 64,
  );
  const e = scalarFromUniformBytes(challenge);
  const lhs = mul(RistrettoPoint.BASE, s);
  const rhs = R.add(mul(P, e));
  return lhs.equals(rhs);
}

// The wallet's sign-script-message signs with the spend key offset by the
// sender-offset DH, which is NOT the key inside a one-sided output's script.
// The key inside the script is mask-derived (key manager:
// stealth_address_script_spending_key):
//   script_pub = spend_pub + from_uniform(H_km("script key", mask)) * G
// So the verifier recovers the wallet's spend public key from the receipt's
// own two values (script key from chain, mask from receipt) and verifies the
// wallet's spend-key message signature (sign-message) under it.
export function deriveSpendPublicKey(scriptPubKeyHex, maskHex) {
  const hash = domainSeparatedHash(
    'com.tari.base_layer.core.transactions.key_manager', 1, 'script key',
    [hexToBytes(maskHex)], 64,
  );
  const offset = mul(RistrettoPoint.BASE, scalarFromUniformBytes(hash));
  const scriptPoint = RistrettoPoint.fromHex(hexToBytes(scriptPubKeyHex));
  return bytesToHex(scriptPoint.subtract(offset).toRawBytes());
}

export function verifyReceiptSignature(scriptPubKeyHex, maskHex, messageBytes, signatureHex) {
  const spendPub = deriveSpendPublicKey(scriptPubKeyHex, maskHex);
  return verifySchnorr(
    'com.tari.base_layer.wallet.message_signing', 1, spendPub, messageBytes, signatureHex,
  );
}

// ---- EncryptedData decryption with the wallet's private view key ----
// encryption_key input to the KDF is the view key's 32 bytes (sender uses the view
// public key bytes; receiver uses the private view key bytes; both are the raw
// 32-byte scalar/point encodings the wallet feeds to kdf_aead).
export function aeadKey(encryptionKeyBytes, commitmentBytes) {
  return domainSeparatedHash(
    'com.tari.base_layer.core.transactions.secure_nonce_kdf', 0, 'encrypted_value_and_mask',
    [encryptionKeyBytes, commitmentBytes], 32,
  );
}

function decryptWithKey(encryptionKeyBytes, commitment, data) {
  const tag = data.slice(0, 16);
  const nonce = data.slice(16, 40);
  const ct = data.slice(40);
  const key = aeadKey(encryptionKeyBytes, commitment);
  const cipher = xchacha20poly1305(key, nonce, ENCRYPTED_DATA_AAD);
  const plain = cipher.decrypt(concat(ct, tag));
  return {
    value: leBytesToBigInt(plain.slice(0, 8)),
    mask: plain.slice(8, 40),
    memoBytes: plain.slice(40),
  };
}

// Mirrors KeyManager::try_output_key_recovery: first the direct view-key path
// (own outputs), then the Diffie-Hellman path used for one-sided payments from
// other wallets: shared_secret = view_priv * sender_offset_pub, and the
// encryption key is from_uniform_bytes(domain hash over the shared secret point).
export function decryptEncryptedData(viewPrivHex, senderOffsetPubHex, commitmentHex, encryptedHex) {
  const commitment = hexToBytes(commitmentHex);
  const data = hexToBytes(encryptedHex);
  const viewPriv = hexToBytes(viewPrivHex);
  try {
    return { ...decryptWithKey(viewPriv, commitment, data), via: 'view-key' };
  } catch { /* not an own output; try the DH path */ }
  const v = scalarFromCanonicalBytes(viewPriv);
  const R = RistrettoPoint.fromHex(hexToBytes(senderOffsetPubHex));
  const sharedSecret = mul(R, v).toRawBytes();
  const hash = domainSeparatedHash(
    'com.tari.base_layer.wallet.output_encryption_keys', 1, '', [sharedSecret], 64,
  );
  const encryptionKey = bigIntToLeBytes(scalarFromUniformBytes(hash));
  return { ...decryptWithKey(encryptionKey, commitment, data), via: 'diffie-hellman' };
}

// ---- MemoField parsing: returns the user payment_id bytes ----
export function parseMemoPaymentId(memoBytes) {
  if (!memoBytes || memoBytes.length === 0) return new Uint8Array();
  const tag = memoBytes[0];
  if (tag === 2) {
    // Open: [tag][tx_type][payment_id...]
    return memoBytes.slice(2);
  }
  if (tag === 5) {
    // AddressAndData: [tag][meta 5][addr_len][address][pid_len][payment_id][padding]
    const addrLen = memoBytes[6];
    const pidLenOff = 7 + addrLen;
    const pidLen = memoBytes[pidLenOff];
    return memoBytes.slice(pidLenOff + 1, pidLenOff + 1 + pidLen);
  }
  if (tag === 6) {
    // TransactionInfo: [tag][amount 8][meta 5][addr_len][address][pid_len][payment_id]...
    const addrLen = memoBytes[14];
    const pidLenOff = 15 + addrLen;
    const pidLen = memoBytes[pidLenOff];
    return memoBytes.slice(pidLenOff + 1, pidLenOff + 1 + pidLen);
  }
  if (tag === 7) return memoBytes.slice(1);
  return memoBytes; // unknown: hand back raw
}

// ---- Tari address (dual, one-sided features) ----
const DAMMSUM_MASK = 27; // 1 + 2^4 + 2^3 + 2^1 from COEFFICIENTS [4,3,1]
export function dammsum(bytes) {
  let result = 0;
  for (const d of bytes) {
    result ^= d;
    const overflow = (result & 0x80) !== 0;
    result = (result << 1) & 0xff;
    if (overflow) result ^= DAMMSUM_MASK;
  }
  return result;
}

const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export function base58Encode(bytes) {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = '';
  while (n > 0n) {
    out = B58_ALPHABET[Number(n % 58n)] + out;
    n /= 58n;
  }
  return '1'.repeat(zeros) + out;
}

// network: 0x26 = Esmeralda, 0x2a? mainnet differs; features 0x01 = one-sided only
export function buildOneSidedAddress(viewPubHex, spendPubHex, networkByte = 0x26) {
  const body = concat(
    new Uint8Array([networkByte, 0x01]),
    hexToBytes(viewPubHex),
    hexToBytes(spendPubHex),
  );
  const full = concat(body, new Uint8Array([dammsum(body)]));
  return (
    base58Encode(full.slice(0, 1)) +
    base58Encode(full.slice(1, 2)) +
    base58Encode(full.slice(2))
  );
}

export function publicKeyFromPrivate(privHex) {
  const scalar = scalarFromCanonicalBytes(hexToBytes(privHex));
  return bytesToHex(mul(RistrettoPoint.BASE, scalar).toRawBytes());
}

// ---- PaidSeal receipt payload + canonical signing form ----
export const RECEIPT_FIELDS = [
  'version', 'network', 'output_commitment', 'amount', 'blinding_factor',
  'script_public_key', 'block_height', 'output_locator', 'payref',
  'payment_memo', 'signed_note', 'issued_to', 'issued_on',
];

export function canonicalReceiptString(p) {
  const lines = ['PAIDSEAL-RECEIPT-V1'];
  for (const f of RECEIPT_FIELDS) {
    lines.push(`${f}=${p[f] ?? ''}`);
  }
  return lines.join('\n');
}

export function receiptMessageHash(p) {
  return sha256(new TextEncoder().encode(canonicalReceiptString(p)));
}

export function encodeReceiptLink(baseUrl, payload) {
  const json = JSON.stringify(payload);
  const b64 = Buffer.from(json, 'utf8').toString('base64url');
  return `${baseUrl}#${b64}`;
}

export function decodeReceiptLink(fragment) {
  const json = Buffer.from(fragment, 'base64url').toString('utf8');
  return JSON.parse(json);
}
