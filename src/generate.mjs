// PaidSeal receipt generator.
//
// Runs locally beside the receiver's Tari console wallet. It never sends the
// view key anywhere: the key is read from the wallet's own export file on this
// machine, used to open exactly one payment output, and the receipt it produces
// contains no key material.
//
// Prerequisites:
//   - minotari_console_wallet (Tari suite v6.3.0-pre.4 or compatible) with a
//     synced wallet that has received a one-sided stealth payment
//   - the wallet password in MINOTARI_WALLET_PASSWORD
//   - sqlite3 on PATH (reads the output hash and PayRef from the wallet DB)
//   - the view key export: run the wallet command
//       export-view-key-and-spend-key
//     and save the two lines ("View key: ..." / "Spend key: ...") to a file.
//
// Usage:
//   node src/generate.mjs --wallet <wallet base path> --wallet-bin <path to minotari_console_wallet> \
//     --keys <view key export file> --amount <microTari> \
//     [--note "..."] [--issued-to "..."] [--base-url https://your-host/verify.html] \
//     [--rpc https://rpc.esmeralda.tari.com] [--network esmeralda]
import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import {
  decryptEncryptedData, parseMemoPaymentId, verifyCommitmentOpening,
  verifyReceiptSignature, receiptMessageHash, canonicalReceiptString,
  bytesToHex, hexToBytes, encodeReceiptLink,
} from './tari.js';

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : fallback;
}

const WALLET_BASE = arg('wallet');
const WALLET_BIN = arg('wallet-bin', 'minotari_console_wallet');
const KEYS_FILE = arg('keys');
const AMOUNT = arg('amount');
const RPC = arg('rpc', 'https://rpc.esmeralda.tari.com');
const NETWORK = arg('network', 'esmeralda');
const BASE_URL = arg('base-url', 'https://example.org/verify.html');
const OUT_FILE = arg('out', 'receipt.json');
if (!WALLET_BASE || !KEYS_FILE || !AMOUNT) {
  console.error('required: --wallet <base> --keys <file> --amount <microTari>');
  process.exit(2);
}
const PW = process.env.MINOTARI_WALLET_PASSWORD;
if (!PW) { console.error('set MINOTARI_WALLET_PASSWORD'); process.exit(2); }

function walletCmd(args) {
  return execFileSync(WALLET_BIN, ['-b', WALLET_BASE, '--network', NETWORK, '-n', '--command-mode-auto-exit', ...args], {
    env: { ...process.env, MINOTARI_WALLET_PASSWORD: PW },
    encoding: 'utf8', maxBuffer: 16 * 1024 * 1024,
  });
}

function parseCsv(text) {
  const unq = (s) => s.trim().replace(/^"|"$/g, '');
  const lines = text.trim().split('\n');
  const head = lines[0].split(',').map(unq);
  return lines.slice(1).map((line) => {
    const cells = line.split(',').map(unq);
    const row = {};
    head.forEach((h, i) => (row[h] = cells[i] || ''));
    return row;
  });
}

async function main() {
  const keysTxt = readFileSync(KEYS_FILE, 'utf8');
  const viewPriv = keysTxt.match(/View key: ([0-9a-f]+)/)[1];

  // 1. Export the wallet's UTXOs and pick the payment to receipt.
  const csvPath = `${WALLET_BASE}/paidseal-utxos.csv`;
  walletCmd(['export-utxos', '-o', csvPath]);
  const rows = parseCsv(readFileSync(csvPath, 'utf8'));
  const target = rows.find((r) => r.value === AMOUNT);
  if (!target) throw new Error(`no unspent output of ${AMOUNT} microTari in this wallet`);

  const commitment = target.commitment;
  const scriptHex = target.script;
  if (!scriptHex.startsWith('7e')) {
    throw new Error('This payment did not use the stealth format. Its script does not carry a one-time key, so a receipt cannot hide the wallet behind it. PaidSeal will not issue a receipt for it.');
  }
  const scriptPubKey = scriptHex.slice(2, 66);
  const senderOffset = target.sender_offset_public_key;

  // 2. Open the sealed payment data locally with the view key.
  const { value, mask, memoBytes } = decryptEncryptedData(viewPriv, senderOffset, commitment, target.encrypted_data);
  const memo = new TextDecoder().decode(parseMemoPaymentId(memoBytes)).replace(/\0+$/g, '');
  const maskHex = bytesToHex(mask);

  // 3. Refuse to issue if the opening does not check out against the chain data.
  if (!verifyCommitmentOpening(commitment, maskHex, value)) {
    throw new Error('the recovered amount and blinding factor do not open the on-chain commitment; refusing to issue');
  }

  // 4. Output hash, height and PayRef from the wallet DB; height cross-checked with the node.
  const dbPath = `${WALLET_BASE}/${NETWORK}/data/wallet/db/console_wallet.db`;
  const dbOut = execFileSync('sqlite3', [dbPath,
    `SELECT lower(hex(hash)), mined_height FROM outputs WHERE lower(hex(commitment))='${commitment}';`],
    { encoding: 'utf8' }).trim();
  const [outputHashHex, dbHeight] = dbOut.split('|');
  const payrefHex = execFileSync('sqlite3', [dbPath,
    `SELECT lower(hex(payref)) FROM payrefs WHERE lower(hex(output_hash))='${outputHashHex}';`],
    { encoding: 'utf8' }).trim();
  const minedInfo = await (await fetch(`${RPC}/get_utxos_mined_info?hashes=${outputHashHex}`)).json();
  const minedHeight = minedInfo?.utxos?.[0]?.mined_in_height;
  if (String(minedHeight) !== String(dbHeight)) {
    throw new Error(`height mismatch: wallet says ${dbHeight}, chain says ${minedHeight}`);
  }

  // 5. Build the payload and sign it with the wallet's spend key.
  const payload = {
    version: 1,
    network: NETWORK,
    output_commitment: commitment,
    amount: value.toString(),
    blinding_factor: maskHex,
    script_public_key: scriptPubKey,
    block_height: String(minedHeight),
    output_locator: outputHashHex,
    payref: payrefHex || '',
    payment_memo: memo,
    signed_note: arg('note', ''),
    issued_to: arg('issued-to', ''),
    issued_on: new Date().toISOString().slice(0, 10),
  };
  const msgHash = receiptMessageHash(payload);
  console.log('canonical payload:\n' + canonicalReceiptString(payload));

  const sigPath = `${WALLET_BASE}/paidseal-sig.json`;
  walletCmd(['sign-message', '--message', bytesToHex(msgHash), '-o', sigPath]);
  const rawBytes = hexToBytes(JSON.parse(readFileSync(sigPath, 'utf8')));
  // The wallet writes the borsh form: two u64-LE length-prefixed 32-byte parts (R, s).
  let sigHex;
  if (rawBytes.length === 80) {
    sigHex = bytesToHex(new Uint8Array([...rawBytes.slice(8, 40), ...rawBytes.slice(48, 80)]));
  } else if (rawBytes.length === 64) {
    sigHex = bytesToHex(rawBytes);
  } else {
    throw new Error(`unexpected signature length ${rawBytes.length}`);
  }

  // 6. Verify our own receipt exactly as the public page will, before issuing it.
  if (!verifyReceiptSignature(scriptPubKey, maskHex, msgHash, sigHex)) {
    throw new Error('signature failed local verification; not issuing');
  }
  payload.signature = sigHex;
  const link = encodeReceiptLink(BASE_URL, payload);
  writeFileSync(OUT_FILE, JSON.stringify({ payload, link }, null, 2));
  console.log('\nRECEIPT LINK:\n' + link);
}

main().catch((e) => { console.error('ERROR:', e.message); process.exit(1); });
