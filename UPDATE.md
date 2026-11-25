# UPDATE.md — for AI agents updating an existing install

You are an agent that already has this repo installed (or your operator does).
You have been asked to update it and claim Testnet FLOP. Follow this in order.
**Do not improvise. Do not run `init`.**

---

## 0. The one rule that matters

> **NEVER run `python technocore_agent.py init` if an identity already exists.**

`init` creates a *second* identity, which silently changes the DID that signs
everything afterwards. That is indistinguishable from losing the DID. Since
v1.2.1 the command refuses when an identity exists — do not try to work around
that refusal. The identity is the whole asset; the code is replaceable.

---

## 1. Find out how it was installed

```bash
cd <repo-dir>            # wherever the repo lives
git rev-parse --is-inside-work-tree 2>/dev/null && echo CLONED || echo ZIP
```

- **`CLONED`** → use section 2A.
- **`ZIP`** (no `.git`) → use section 2B.

If you cannot find the directory, search for it:

```bash
find ~ -maxdepth 4 -name technocore_agent.py 2>/dev/null
```

---

## 2A. Installed with git (preferred)

```bash
cd <repo-dir>
git stash list                 # note anything uncommitted
git pull origin main
```

Verify the update landed:

```bash
grep -c FAUCET_HOSTS technocore_agent.py     # must be > 0
python technocore_agent.py --version         # must be 1.3.0 or newer
```

`git pull` **cannot** touch your identity: `identity.pem` and `passphrase*` are
in `.gitignore`, and they are not tracked. If `git pull` reports a conflict on
`technocore_agent.py` because you edited it locally, keep your edits aside and
re-apply them rather than overwriting the upstream file blindly:

```bash
git diff technocore_agent.py > /tmp/my-local-edits.patch
git checkout -- technocore_agent.py
git pull origin main
git apply /tmp/my-local-edits.patch   # only if you actually need those edits
```

---

## 2B. Installed from a ZIP (no git)

You cannot `git pull`. Replace **only the code and docs**, never the identity:

```bash
cd <repo-dir>
cp technocore_agent.py technocore_agent.py.bak-$(date +%s)   # keep a rollback
curl -fsSL -o technocore_agent.py.new \
  https://raw.githubusercontent.com/zannyzette/technocore-did-gameplay/main/technocore_agent.py
python -c "import ast,sys; ast.parse(open('technocore_agent.py.new').read())" && \
  mv technocore_agent.py.new technocore_agent.py
curl -fsSL -o README.md https://raw.githubusercontent.com/zannyzette/technocore-did-gameplay/main/README.md
```

Never download over `identity.pem`, `passphrase.txt`, `proof.json`, or
`rotation.json`.

---

## 3. Prove the identity is untouched (do this before claiming)

```bash
# DID must be the SAME one you had before the update
python technocore_agent.py did --passphrase-file <your-passphrase-file>
```

Record that DID. If it differs from what you had before the update, **stop** —
something created a new identity. Do not claim, do not post, report to your
operator.

Also confirm no stray second identity exists:

```bash
find ~ -maxdepth 3 -name identity.pem 2>/dev/null    # expect exactly one
```

---

## 4. Claim Testnet FLOP (10 FLOP, no wallet needed)

Your `did:key` **is** an Ed25519 key, so it already owns an SS58 address. There
is nothing to connect, no seed to import, no extension to install.

```bash
python technocore_agent.py faucet                                  # address + both networks
python technocore_agent.py faucet --claim --dry-run                # see exactly what will be sent
python technocore_agent.py faucet --claim                          # Testnet: 10 FLOP, signed
python technocore_agent.py balance                                 # confirm on chain
```

`balance` must show `FREE 10.0 FLOP`. A grant that has not landed yet shows
`akun belum ada di chain` / `account not on chain yet` — that is normal right
after a claim, not a failure.

Devnet is a different network with different rules (25 FLOP, plain POST):
`faucet --claim --network devnet`. Do not confuse the two; the Testnet is the
one the FLOP campaign runs on.

---

## 5. Claim rules you must not break

| Rule | Consequence |
|---|---|
| **Never retry a refusal in a loop** | Refusals carry `reason` + `retryAfterSeconds`. Looping gets the IP throttled (`ip_cooldown`, up to 24 h). |
| **One claim per rolling 24 h per wallet** | The second claim is refused; that is expected, not an error to fix. |
| **Repeating the same nonce is safe** | It returns the same transaction and never pays twice. Use it to re-check a request. |
| **A new nonce only after the previous request reached a final result** | Otherwise you cannot tell which request paid. |
| **A repeat grant may need on-chain spend** | `rolloverRequiresSpend: true` — the faucet can refuse `agent_spend_missing` until the previous grant is used. Report that to your operator instead of hammering the endpoint. |

If you want this to repeat daily, schedule it — do not poll:

```bash
# cron example: check every 2 hours, the script itself enforces the 24h gap
0 */2 * * * cd <repo-dir> && python technocore_agent.py faucet --claim >> claim.log 2>&1
```

Better: gate on state so you do not fire refusals. Keep the last successful
claim timestamp and skip until `now - last >= 24h + margin`.

---

## 6. Other lanes (do not improvise these)

If your operator asks about the other two FLOP lanes, point them at
[PATHS.md](PATHS.md) — it has the full how-to for each:

| Lane | Reality right now |
|---|---|
| Validator | Registration is open (GitHub issue form), but the **signed Testnet joining kit is not published**. Do not generate session keys or sign before it is out. |
| Miner | Devnet pack exists; the **Testnet pack does not**. Devnet stake and calibration do not carry over. Rehearse on Devnet and keep it running. |

Do not register your operator for a validator seat, rent hardware, or bond stake
on your own initiative. Those cost money and are the operator's decision.

## 7. Report back with numbers

When you are done, report exactly this, with real output — not a summary of
intentions:

```
repo version : 1.3.0        (python technocore_agent.py --version)
DID unchanged: yes/no       (did before == did after)
SS58         : 5...
claim result : funded 10 FLOP, tx 0x..., status finalized
balance      : FREE 10.0 FLOP  (python technocore_agent.py balance)
refusal      : none | reason=<code>, retryAfterSeconds=<n>
```

If anything failed, say which step and paste the actual error line. Do not
report success you did not verify on chain.
