// PaidSeal verification page logic. Runs entirely in the browser:
// receipt data comes from the URL fragment (never sent to any server),
// chain data comes from Tari's public node HTTP API (GET requests only).
import {
  verifyCommitmentOpening, verifyReceiptSignature, receiptMessageHash,
} from './tari.js';

const NODE_BASE = 'https://rpc.esmeralda.tari.com';
const NODE_NAME = 'Tari public node (rpc.esmeralda.tari.com), Esmeralda testnet';

const $ = (id) => document.getElementById(id);

function setStep(id, state, text) {
  const el = $(id);
  el.className = `step ${state}`;
  el.querySelector('.step-text').textContent = text;
}

function fail(title, detail) {
  $('verdict').className = 'verdict fail';
  $('verdict-title').textContent = title;
  $('verdict-detail').textContent = detail;
  $('sections').style.display = 'none';
}

function formatAmount(micro) {
  const v = BigInt(micro);
  const whole = v / 1000000n;
  const frac = (v % 1000000n).toString().padStart(6, '0').replace(/0+$/, '');
  return frac ? `${whole}.${frac}` : `${whole}`;
}

async function getJson(path) {
  const res = await fetch(`${NODE_BASE}${path}`);
  if (!res.ok) throw new Error(`node returned HTTP ${res.status}`);
  return res.json();
}

async function main() {
  const frag = location.hash.replace(/^#/, '');
  if (!frag) {
    fail('No receipt in this link', 'This page verifies PaidSeal receipts. The receipt data travels in the part of the link after the # symbol. Open a full PaidSeal receipt link to check a payment.');
    return;
  }
  let p;
  try {
    p = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(frag.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0))));
  } catch {
    fail('This receipt link is damaged', 'The receipt data in the link could not be read. Ask the person who sent it to issue a fresh copy.');
    return;
  }
  $('receipt-body').style.display = 'block';

  try {
    // Step 1: fetch the output from the chain
    setStep('step-fetch', 'run', 'Fetching the payment output from the chain...');
    const fetched = await getJson(`/fetch_utxo?utxo=${p.output_locator}`);
    const output = Array.isArray(fetched) ? fetched[0] : fetched;
    if (!output || !output.commitment) throw new Error('output not found on chain');
    if (output.commitment !== p.output_commitment) {
      setStep('step-fetch', 'bad', 'The on-chain output does not match this receipt.');
      return fail('This receipt does not verify', 'The output this receipt points to has a different commitment on chain. The receipt was not issued for that output.');
    }
    setStep('step-fetch', 'ok', 'Output found on chain, commitment matches.');

    // Step 2: the script key inside the on-chain output
    setStep('step-script', 'run', 'Checking the key inside the payment output...');
    const script = output.script || '';
    const onChainKey = script.startsWith('7e') ? script.slice(2, 66) : '';
    if (onChainKey !== p.script_public_key) {
      setStep('step-script', 'bad', 'The key in the on-chain output does not match this receipt.');
      return fail('This receipt does not verify', 'The signature key named in this receipt is not the key inside the on-chain payment output, so the signature is not anchored to this payment.');
    }
    setStep('step-script', 'ok', 'The receipt is anchored to the key inside this payment output.');

    // Step 3: amount + blinding factor open the commitment
    setStep('step-open', 'run', 'Opening the commitment with the amount and blinding factor...');
    const opens = verifyCommitmentOpening(p.output_commitment, p.blinding_factor, BigInt(p.amount));
    if (!opens) {
      setStep('step-open', 'bad', 'The amount and blinding factor do not open the commitment.');
      return fail('This receipt does not verify', 'The amount and blinding factor in this receipt do not match the sealed amount in the on-chain output. The receipt has been edited or was issued for a different payment.');
    }
    setStep('step-open', 'ok', 'Amount and blinding factor open the on-chain commitment.');

    // Step 4: signature over the full receipt, under the script key
    setStep('step-sig', 'run', 'Verifying the receiver signature...');
    const msgHash = receiptMessageHash(p);
    let sigOk = false;
    try { sigOk = verifyReceiptSignature(p.script_public_key, p.blinding_factor, msgHash, p.signature); } catch { sigOk = false; }
    if (!sigOk) {
      setStep('step-sig', 'bad', 'The signature does not verify.');
      return fail('This receipt does not verify', 'The signature does not match the receipt contents under the payment output key. Something in this receipt was changed after it was issued.');
    }
    setStep('step-sig', 'ok', 'Signature verified. Nothing in this receipt was changed after issue.');

    // Chain facts: height, time, confirmations
    const mined = await getJson(`/get_utxos_mined_info?hashes=${p.output_locator}`);
    const info = mined?.utxos?.[0] ?? (Array.isArray(mined) ? mined[0] : mined);
    const tip = await getJson('/get_tip_info');
    const tipHeight = tip?.metadata?.best_block_height ?? tip?.tip_info?.metadata?.best_block_height;
    const minedHeight = info?.mined_in_height;
    const minedTs = info?.mined_in_timestamp;
    if (String(minedHeight) !== String(p.block_height)) {
      return fail('This receipt does not verify', `The receipt names block ${p.block_height} but the chain says this output was mined in block ${minedHeight}.`);
    }
    const confirmations = (tipHeight != null && minedHeight != null) ? (tipHeight - minedHeight + 1) : null;

    // Fill the sections
    $('amount').textContent = `${formatAmount(p.amount)} XTM`;
    $('time').textContent = minedTs ? new Date(minedTs * 1000).toUTCString() : `Block ${minedHeight}`;
    $('height').textContent = `${minedHeight}`;
    $('memo').textContent = p.payment_memo || '(no memo on this payment)';
    $('note').textContent = p.signed_note || '(no note)';
    $('issued-to').textContent = p.issued_to || '';
    $('issued-on').textContent = p.issued_on || '';
    $('source-line').textContent =
      `Checked against the Tari chain using ${NODE_NAME}. ` +
      (confirmations != null ? `This payment has ${confirmations} confirmations. ` : '') +
      'If you want more certainty, check a second source.';

    $('verdict').className = 'verdict ok';
    $('verdict-title').textContent = 'This receipt verifies';
    $('verdict-detail').textContent = 'Every check below passed against the live Tari chain, in your browser. No server held this receipt or saw its contents.';
    $('sections').style.display = 'block';
  } catch (e) {
    fail('Could not complete the check', `Something went wrong while checking this receipt against the chain (${e.message}). Check your connection and reload to try again.`);
  }
}

main();
