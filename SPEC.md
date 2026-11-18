# PaidSeal receipt format: one-page spec (v1)

Status: implemented and verified end to end on the Esmeralda testnet, 2026-11-18.
Design: `paid-receipt-design-locked.md` (locked by Dexter, 2026-11-17). This spec fixes the
build-time choices the design left open: canonical encoding, signature scheme, error states.

## The receipt

A receipt is a JSON object carried in the fragment of a verification-page URL
(`verify.html#<base64url(json)>`). Browsers never send the fragment to a server, so the
amount, memo and blinding factor appear in no server logs, referrer headers or link previews.

Fields, in canonical order:

| field | content |
|---|---|
| version | `1` |
| network | `esmeralda` (testnet) or `mainnet` |
| output_commitment | hex, 32 bytes: the on-chain Pedersen commitment of the payment output |
| amount | decimal string, amount in microTari (1 XTM = 1,000,000) |
| blinding_factor | hex, 32 bytes: the commitment mask, recovered by the receiving wallet |
| script_public_key | hex, 32 bytes: the one-time key inside the output's script |
| block_height | decimal string: block the output was mined in (cross-checked against the chain) |
| output_locator | hex, 32 bytes: the output hash, the public node's lookup key |
| payref | hex, 32 bytes, may be empty: Tari PayRef, human-facing reference |
| payment_memo | the payment memo the receiving wallet opened from the payment (may be empty) |
| signed_note | the receiver's note for this copy of the receipt |
| issued_to | who this copy was issued to (a signed label, not a lock) |
| issued_on | issue date, `YYYY-MM-DD` |
| signature | hex, 64 bytes: CheckSig Schnorr signature, `R || s` |

## Canonical encoding and signature

The signed message is the SHA-256 hash of the canonical string: the line `PAIDSEAL-RECEIPT-V1`
followed by one `field=value` line per field above (excluding `signature`), in the order
listed, joined with `\n`, encoded as UTF-8.

The signature is produced by the receiving wallet itself, with Tari's shipped `sign-message`
command: the wallet signs the 32-byte message hash with its spend key. The scheme is Tari's
message-signing Schnorr over Ristretto255: challenge = domain-separated Blake2b-512
(`com.tari.base_layer.wallet.message_signing.v1.challenge`) over `R || P || message`,
wide-reduced mod l; verification is `s.G == R + e.P`.

The verifier recovers the spend public key from the receipt itself. Tari's one-sided outputs
carry a mask-derived script key (key manager `stealth_address_script_spending_key`):

    script_pub = spend_pub + from_uniform(H_km("script key", mask)) . G

so `spend_pub = script_pub - from_uniform(H_km("script key", mask)) . G`, computed from the
on-chain script key and the receipt's blinding factor. Only the wallet that owns the output
can produce this signature, and only for a receipt whose mask truly belongs to that output:
a forged mask would derive a different spend key and the signature would fail. (The shipped
`sign-script-message` command was evaluated first and rejected: it signs with the spend key
offset by the sender-offset Diffie-Hellman secret, which is not the key inside a one-sided
output's script. Verified against source and on chain, 2026-11-18.)

One honest consequence of the mask derivation: anyone holding a receipt can derive the
issuing wallet's spend public key from it, so two receipts from the same wallet can be
recognised as coming from the same wallet. They still name no address, reveal no balance and
expose no other payment. This is a property of Tari's one-sided construction, recorded here
rather than hidden.

## How the generator recovers the blinding factor

Stock Tari tooling deliberately never exports the mask. The receiving wallet, however,
recovers it when it scans the payment: the output's `encrypted_data` is an XChaCha20-Poly1305
sealed blob (layout `tag || nonce || ciphertext`, AAD `TARI_AAD_VALUE_AND_MASK_EXTEND_NONCE_VARIANT`)
holding `value || mask || memo`. The AEAD key is a domain-separated Blake2b-256
(`com.tari.base_layer.core.transactions.secure_nonce_kdf.v0.encrypted_value_and_mask`) over the
view key bytes and the commitment. The generator runs locally beside the wallet, reads the
private view key from the wallet's own export, decrypts the one chosen output, and checks the
recovered (value, mask) against the on-chain commitment before it will sign anything. The view
key never leaves the receiver's machine and never appears in the receipt.

Revealing the mask is safe: spending a Tari output also needs the script private key, which is
derived from the mask together with the wallet's master spend key. The mask alone cannot yield
it (Tari chain spike, Q9, verified against source).

## Verification steps (the page, in order)

1. Fetch the output by `output_locator` from the named public node (`/fetch_utxo`).
   The returned commitment must equal `output_commitment`.
2. Extract the PushPubkey key from the on-chain output's script. It must equal `script_public_key`.
3. Check `blinding_factor` and `amount` open the commitment: `C == mask.G + amount.H`
   (Ristretto255 Pedersen, H = NUMS point `ce389841...71d70`).
4. Recompute the canonical string and SHA-256. Recover the signer's public key as
   `spend_pub = script_pub - from_uniform(H_km("script key", blinding_factor)) . G` and verify
   `signature` under it.
5. Fetch mined info (`/get_utxos_mined_info`): height must equal `block_height`; the displayed
   time is the chain's mined timestamp. Confirmations = tip height - mined height + 1
   (`/get_tip_info`). The page names its chain source.

Display: three separated sections (Chain verified / Payment memo / Signed note), then the
honesty box. The memo is shown as signature-covered, not chain-verified.

## Error states

- No fragment, or fragment that does not decode: the page says there is no receipt in the link.
- Output not found, or commitment mismatch: "does not verify", naming the failed step.
- Script key mismatch: "does not verify" (signature not anchored to this payment).
- Commitment does not open: "does not verify" (receipt edited or issued for another payment).
- Signature invalid: "does not verify" (contents changed after issue).
- Block height mismatch with the chain: "does not verify".
- Node unreachable or HTTP error: "could not complete the check", with the error, and a
  prompt to reload. This is never shown as a failed receipt.

## Refusals (generator)

- If the recovered (value, mask) does not open the on-chain commitment, the generator stops
  and issues nothing.
- Payments in the old linkable one-sided format (wallet main key in the script) are refused
  in plain words: a receipt cannot hide that the wallet key is on chain. (In current Tari
  every one-sided send is stealth by default, so this guards genuinely old outputs only.)
