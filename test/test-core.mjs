// Core crypto tests. The domain-hash vectors are taken from tari_crypto's own
// test suite (src/hashing.rs), so a pass here means this implementation hashes
// exactly the way Tari does.
import {
  domainSeparatedHash, bytesToHex, base58Encode, dammsum,
  verifyCommitmentOpening, publicKeyFromPrivate, hexToBytes,
  deriveSpendPublicKey,
} from '../src/tari.js';

const enc = new TextEncoder();
let fails = 0;
function check(name, got, want) {
  const ok = got === want;
  if (!ok) fails++;
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${ok ? '' : `\n  got  ${got}\n  want ${want}`}`);
}

check(
  'domain hash com.tari.generic/test_hasher',
  bytesToHex(domainSeparatedHash('com.tari.generic', 1, 'test_hasher', [enc.encode('some foo')], 32)),
  'a8326620e305430a0b632a0a5e33c6c1124d7513b4bd84736faaa3a0b9ba557f',
);
check(
  'domain hash com.discworld v42',
  bytesToHex(domainSeparatedHash('com.discworld', 42, 'turtles', [enc.encode('elephants')], 64)),
  '64a89c7160a1076a725fac97d3f67803abd0991d82518a595072fa62df4c870bddee9160f591231c381087831bf6925616013de317ce0b02846585caf41942ac',
);
check(
  'domain hash com.tari.mac',
  bytesToHex(domainSeparatedHash('com.tari.mac', 1, 'test',
    [hexToBytes('b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c'), enc.encode('test message')], 32)),
  '9bcfbe2bad73b14ac42f673ddca34e82ce03cbbac69d34526004f5d108dff061',
);

// Esmeralda network byte encodes to 'f', one-sided features byte to '2':
// real Tari one-sided addresses on Esmeralda start with "f2".
check('base58 network byte', base58Encode(new Uint8Array([0x26])), 'f');
check('base58 features byte', base58Encode(new Uint8Array([0x01])), '2');

// DammSum: appending the checksum makes the whole slice checksum to zero.
const body = hexToBytes('2601' + '11'.repeat(32) + '22'.repeat(32));
check('dammsum zero property', String(dammsum(new Uint8Array([...body, dammsum(body)]))), '0');

// Pedersen generators: mask=1, value=0 gives G; mask=0, value=1 gives H.
check(
  'pedersen G sanity',
  String(verifyCommitmentOpening(
    'e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76',
    '0100000000000000000000000000000000000000000000000000000000000000', 0n)),
  'true',
);
check(
  'pedersen H sanity',
  String(verifyCommitmentOpening(
    'ce389841c0c8698ab95b70242aeea64840b1eac5f644b7d008ac0587cf471d70',
    '0000000000000000000000000000000000000000000000000000000000000000', 1n)),
  'true',
);

// Private key 1 belongs to the base point.
check(
  'public key of scalar 1',
  publicKeyFromPrivate('0100000000000000000000000000000000000000000000000000000000000000'),
  'e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76',
);

// Spend key recovery: script_pub - H("script key", mask).G must invert the
// key manager's derivation. With mask such that the offset is the base point
// multiple of a known scalar this is covered end to end by the live demo;
// here we only check the function round-trips a synthetic pair.
{
  const mask = '0700000000000000000000000000000000000000000000000000000000000000';
  const { ed25519, RistrettoPoint } = await import('@noble/curves/ed25519');
  const { domainSeparatedHash: dsh, scalarFromUniformBytes } = await import('../src/tari.js');
  const h = scalarFromUniformBytes(dsh('com.tari.base_layer.core.transactions.key_manager', 1, 'script key', [hexToBytes(mask)], 64));
  const spend = RistrettoPoint.BASE.multiply(3n);
  const script = spend.add(RistrettoPoint.BASE.multiply(h));
  const recovered = deriveSpendPublicKey(bytesToHex(script.toRawBytes()), mask);
  check('spend key recovery round-trip', recovered, bytesToHex(spend.toRawBytes()));
}

console.log(fails === 0 ? 'ALL PASS' : `${fails} FAILURES`);
process.exit(fails ? 1 : 0);
