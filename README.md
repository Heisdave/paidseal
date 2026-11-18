# PaidSeal

**Prove you got paid. Show nothing else.**

A contributor gets paid in Tari by a DAO, a grant program, a bounty platform or a client, and generates a shareable receipt that proves the exact amount arrived at a specific time, without revealing their wallet, balance, or any other transaction.

Entry for the Tari November Build Contest. Live on the Esmeralda testnet.

## The problem

Third parties ask freelancers and contributors to prove income: a landlord, a lender, an accountant. The person who paid you does not need the proof. They have their own records.

On a public chain, proof means a transaction link that exposes the wallet and its history forever. On a private chain like Tari, the payment is hidden, so there is nothing to show. What people actually use today is a screenshot, which proves nothing and leaks everything around it.

## How PaidSeal works

1. The payer sends a normal one-sided stealth payment on Tari, with the invoice or bounty reference in the payment memo. The amount, a secret opening value and the memo are sealed inside the payment output. Only the receiver's wallet can open it.
2. The receiver runs the PaidSeal generator beside their wallet. It opens that one output, checks the opening against the chain, signs a receipt covering the amount, the memo, a note, who the receipt is issued to and the issue date, and produces a link.
3. Anyone with the link opens the verification page. The page fetches the output from Tari's public node, re-checks the proof and the signature in the browser, and shows the result. No Tari wallet is needed to check a receipt, and no server ever holds receipt data: everything travels in the part of the link after the `#`, which browsers never send to a server.

The receipt format, the canonical signing form and the error states are specified in [SPEC.md](SPEC.md).

## Try it

- Verification page: (live link added at submission)
- A real receipt, issued for a real testnet payment of 25 XTM with the memo "Invoice #47 - Website redesign": (link added at submission)

Open the receipt link and watch the four checks run against the live chain. Then change one digit of the amount inside the link and reload: the receipt fails, in plain words, at the exact check that caught it.

## Run the generator

You need the Tari console wallet (suite v6.3.0-pre.4 or compatible), Node 20+, and `sqlite3`.

```sh
npm install
# once, in your wallet: export your view key (it never leaves your machine)
minotari_console_wallet -b <wallet> --network esmeralda export-view-key-and-spend-key > keys.txt

MINOTARI_WALLET_PASSWORD=<your password> npm run generate -- \
  --wallet <wallet base path> --wallet-bin <path to minotari_console_wallet> \
  --keys keys.txt --amount <amount in microTari> \
  --note "Payment for Invoice #47" --issued-to "My landlord" \
  --base-url https://<where you host web/verify.html>
```

The generator refuses to issue if the recovered amount and blinding factor do not open the on-chain commitment, and it verifies its own signature the same way the public page will before it prints the link.

## What a receipt proves, and what it does not

A receipt proves a payment of exactly the shown amount arrived in a Tari wallet at the shown time, and that the receipt was issued by that wallet. It cannot be forged or edited by anyone else.

A receipt does not prove who sent the payment. It does not prove the money is still in the wallet. It does not prove the payment was for genuine work: a person can pay themselves from a second wallet and receive a perfectly valid receipt. The verification page says all of this on its face, in the honesty box under the result.

Receipts stay verifiable after the money is spent: Tari's public nodes are archival, and the page checks the output by its hash, spent or not.

## What we learned building this (building blocks tested)

- **The mask is never exported, on purpose.** Stock Tari tooling withholds the blinding factor because mask plus script private key would hand over the spend key. The receiver's wallet still recovers the mask when it scans a payment, from the output's sealed data. The generator re-derives it locally from the wallet's own view key export: DH shared secret with the sender offset key, domain-separated key derivation, XChaCha20-Poly1305 opening. Revealing the mask alone is safe. Spending also needs the script key, which needs the master spend key.
- **`sign-script-message` signs with the wrong key for this job.** It signs with the spend key offset by the sender-offset Diffie-Hellman secret. The key inside a one-sided output's script is a different derivation: the spend key offset by a hash of the commitment mask. So PaidSeal signs with the wallet's spend key (`sign-message`), and the verifier recovers that public key from the receipt itself: `spend_pub = script_pub - H("script key", mask).G`. The signature stays anchored to the exact output.
- **That derivation cuts both ways.** Anyone holding a receipt can derive the issuing wallet's spend public key, so two receipts from one wallet can be recognised as coming from the same wallet. They still name no address and expose no balance or other payment. This is a property of Tari's one-sided construction, recorded here rather than hidden.
- **Browser verification needs no WASM and no backend.** Ristretto255 Pedersen openings and Tari's Schnorr signatures check out in plain JavaScript (noble curves and hashes), and Tari's public nodes answer browser GET requests with open CORS. The whole verifier is one static page.
- **Spent outputs stay fetchable.** Tari nodes default to archival storage (pruning horizon 0, confirmed live on the public testnet and mainnet nodes), and the node's output index keeps spent outputs. Proof of income usually concerns money already spent, so this mattered.

## Layout

- `src/tari.js`: the Tari cryptography core (domain-separated hashing, sealed-data opening, Pedersen and Schnorr checks, address encoding), mirrored from Tari source and pinned to its published test vectors.
- `src/generate.mjs`: the receipt generator, run beside the receiver's wallet.
- `src/verify-main.js` and `web/`: the static verification page.
- `test/test-core.mjs`: `npm test`.
- `SPEC.md`: the receipt format spec.

## License

MIT. Built on Tari (BSD-3-Clause) primitives and public infrastructure.
