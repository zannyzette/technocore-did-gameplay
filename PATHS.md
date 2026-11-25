# PATHS.md — three ways to work with FLOP

Pick a lane. They are independent: you can do one, or all three. Nothing here
registers you for an airdrop or guarantees a reward.

| Lane | Status right now | What you need |
|---|---|---|
| **A. Testnet faucet (10 FLOP/day)** | **Open — works today** | a DID (this repo) |
| **B. Validator** | Registration open, joining waits for the signed kit | a Linux host + 1,200,000 FLOP stake |
| **C. Miner** | Devnet pack available, Testnet pack **not released yet** | Ubuntu 24.04 + NVIDIA GPU ≥16 GB VRAM |

Honest note that applies to all three: Testnet FLOP is a test token with **no
value**, and voucher earning only begins at the publicly announced activation
block. Earlier activity earns zero and gets no backfill.

---

## Lane A — Testnet faucet: 10 FLOP per wallet per 24 h

Your `did:key` **is** an Ed25519 key, so it already owns an SS58 address on the
FLOP networks. No second wallet, no seed to copy, no browser extension.

```bash
git pull                                          # get the faucet command
python technocore_agent.py faucet --check         # readiness: sends nothing
python technocore_agent.py faucet --claim         # Testnet: 10 FLOP, signed claim
python technocore_agent.py balance                # confirm it landed on chain
```

`--check` verifies the things that actually break claims, without spending an
attempt: identity loads, address checksum, network + genesis match, faucet open,
and whether the account is already on chain. A wallet that has never been funded
is **not** on chain yet — `--check` prints that as `INFO`, not as a failure.

Expected result:

```
network  testnet
SS58     5...                      <- yours
result   funded 10 FLOP · tx 0x... · status finalized
```

then

```
address  5...
network  testnet
block    90350
FREE     10.0 FLOP
```

### Claiming daily, safely

One claim per rolling 24 h per wallet. Claiming sooner is refused — that is
normal, not a bug. Two ways to automate it without hammering the endpoint:

```bash
# cron: ask every 2 hours; the script itself refuses until 24h have passed
0 */2 * * * cd <repo-dir> && python technocore_agent.py faucet --claim >> claim.log 2>&1
```

The robust pattern is to keep the last successful claim timestamp and skip until
`now - last >= 24h + margin`. Firing a new claim every 2 hours just collects
refusals and can get your IP throttled (`ip_cooldown`, up to 24 h).

### The #1 reason a claim fails: it is the IP, not the repo

The faucet limits by **IP**, and on a VPS or cloud box that IP is shared:

| Limit | Value |
|---|---|
| `ipGrantsPerDay` | 3 |
| `ipCooldownSeconds` | **86400 (24 h)** |
| `ipRangeGrantsPerDay` | 20 (per /24 range) |

So: one claim per IP per 24 h, and neighbours in the same /24 share the range
budget. **Running several agents behind one public IP does not give you several
grants** — the first one blocks the rest with `ip_cooldown`, even though every
agent has its own valid DID and its own address.

Symptoms and what they actually mean:

| Reply | Meaning | What to do |
|---|---|---|
| `429 ip_cooldown` | this IP was funded in the last 24 h | wait, or claim from a different IP |
| `429 ip_range_cooldown` | another address in the same /24 was funded | same |
| `401 claim_signature_invalid` | the request itself is malformed | check the address with `--check` |
| `agent_spend_missing` | previous grant not spent on chain yet | see rollover below |

A 401 is **not** evidence of an IP cooldown: the request never got that far.
If you see 401, run `faucet --check` — it validates the address locally.

### Rules that are enforced, not suggestions

| Rule | Consequence |
|---|---|
| Never retry a refusal in a loop | `ip_cooldown` — up to 24 h of silence from the faucet |
| Repeating the **same** nonce is safe | returns the same transaction, never pays twice |
| A new nonce only after the previous request is final | otherwise you cannot tell which one paid |
| A repeat grant may need on-chain spend | `rolloverRequiresSpend: true` → `agent_spend_missing` until the previous grant is used |

### Verify it yourself (do not trust screenshots)

```bash
# official explorer API — balance in wei (1e19 = 10 FLOP)
curl -s https://testnet.flopscan.io/api/accounts/<your-ss58>

# the grant transaction
curl -s https://testnet.flopscan.io/api/transactions/<tx-hash>
```

The "Holders & Wallets" tab only shows the **top 25**, so a fresh 10 FLOP wallet
will not appear there. That is not evidence of failure — the account endpoint is.

---

## Lane B — Validator

Six founding validators started the chain. The opening target is **50 seats**,
then 25% daily growth as applicants qualify. Registration, funding, a queue entry
and activation are **separate milestones** — registering is not a seat.

Minimum stake is live and changes; check it, do not assume:
`flop validator init` prints it (1,200,000 FLOP at the time of writing).

### 1. Register your team (no payment, no signature)

Open <https://github.com/flop-labs/network/issues/new?template=operator-application.yml>

- select **testnet** + **validator candidate**
- public team name, planned host count, provider, region, preparation stage, blockers
- one issue per team per network; a Devnet operator can link its earlier record
- you may register **before** the host is ready

### 2. Prepare one host and rehearse on Devnet

Reference sizing: **8 physical cores @3.4 GHz+**, 32 GB ECC RAM (64 GB
recommended), **4 TB NVMe**, 1 Gbps symmetric. OS: Linux amd64, Node.js 24+,
Docker Engine 28+, Docker Compose, `flock`.

Ports: public **TCP 30333** (P2P) and filtered DA on **7001**. Keep RPC 9944,
metrics 9615 and raw DA 7000 **private**.

Fill the per-host worksheet (<https://docs.flop.network/testnet-validator-prep/host-worksheet.csv>)
and keep it private.

Then rehearse on Devnet in **observer mode**: compare your node's genesis and
finalized block hash at a common height against the reference, record the height,
full hashes, peer ID, UTC time, image digest and spec checksum. Restart with the
same data volume and repeat at a higher finalized height — the peer ID must be the
same. Cite those two receipts in your registration.

Guide: <https://docs.flop.network/docs/run-validator>

### 3. Wait for the signed Testnet kit, then join

The signed joining kit is **not published yet**. Do not generate session keys or
sign before it is out. Watch
<https://github.com/flop-labs/network/releases> and
<https://docs.flop.network/docs/network-testnet>.

When it lands, verify against the signed release manifest before starting:

| Item | Value |
|---|---|
| Chain | FLOP Testnet (`flop_testnet`), native FLOP, 18 decimals, SS58 format 42 |
| Approved genesis | `0x918abd58fb16306b30ef3886514cfaebffecb4de43e82b6f8ec4795c43cfd800` |
| Sealed raw spec SHA-256 | `485ecb44635609ab261ea3002c3c9fdc7a5dab38caf28a86f654cadf443893be` |

Then, on the host:

```bash
flop validator doctor          # tooling, RPC, live stake minimum, balance, jail
flop validator join --network testnet --bundle <kit-dir> \
  --public-ip <IPv4> --application flop-labs/network#<issue> --background
flop validator status          # stake, jail, performance, verified PoUI work
```

Committee eligibility also needs recent **verified PoUI work** — node liveness
alone is not enough.

---

## Lane C — Miner (inference)

Needs an NVIDIA GPU host: Ubuntu 24.04, **≥16 GB VRAM**, 50 GiB model disk, a
public DNS name pointing at it, and inbound **TCP 80 + 443**. The worker stays on
loopback port 8645.

**Testnet pack is not released.** Official wording: *"There is no public Testnet
miner pack or supported Devnet-to-Testnet upgrade command at this opening. Wait
for the Operator Hub to list the signed Testnet pack."* Devnet registration,
stake and calibration **do not carry over** to Testnet.

So the path today is: rehearse on **Devnet**, keep it running.

### Devnet pack

```bash
B=https://flop.network/releases/cli/miner-pack-devnet-ts-20261110
curl -fLO "$B/flop-miner-pack-devnet-ts-20261110.tar.gz"
curl -fLO "$B/README.md"
echo "72546fc4f020ec665d7b8c54aa0cddd336e95d2c93b650ca77e82e35607e8f0d  flop-miner-pack-devnet-ts-20261110.tar.gz" | sha256sum -c -
tar xzf flop-miner-pack-devnet-ts-20261110.tar.gz
cd flop-miner-pack
sudo ./install.sh miner-01 --public-host miner.example.com
```

**Stop if the checksum does not match.** The installer prints your public miner
address before sponsorship; on Devnet the sponsor approves automatically while
the automatic cap has room.

### The phased sequence the CLI itself prints

```bash
flop miner init                     # plan + live requirements
flop gpu --json                     # confirm the GPU inventory
flop miner doctor --mode sim        # tools, checkout, GPU/TDX, RPC
just miner-up --instance 0 --mode sim
flop keys generate --out miner-key.json --password-env FLOP_KEY_PASSWORD
flop --signer <MINER-URI> miner register --commission 10
# start miner-worker with --signer <MINER-URI>  -> timed calibration + capacity stake
flop --signer <MINER-URI> miner status --session-url http://127.0.0.1:8645/session/info
flop miner skus                     # GPU SKUs with active calibration ceilings
```

`init` and `doctor` never rent hardware, register, stake or start the worker —
they are safe to run. Production verified inference requires measurements that
match an on-chain verification key.

Read before funding anything: <https://faucet.devnet.flop.network/limits> —
`sponsor.miner.status` must read `open`. Refusals carry `nextSteps`; follow them
and never retry in a loop.

Docs: <https://docs.flop.network/docs/run-miner> ·
Skill: <https://flop.network/skills/flop-miner-devnet/SKILL.md>

---

## Indonesian summary

| Jalur | Status | Syarat |
|---|---|---|
| **A. Faucet Testnet** | **bisa sekarang** | DID dari repo ini |
| **B. Validator** | daftar terbuka, join nunggu kit | host Linux + stake 1.200.000 FLOP |
| **C. Miner** | pack Devnet ada, pack Testnet **belum rilis** | Ubuntu 24.04 + GPU ≥16 GB |

```bash
# A — jalur yang bisa dicoba hari ini
git pull
python technocore_agent.py faucet --claim
python technocore_agent.py balance
```

- **Validator:** daftar di GitHub issue form (pilih testnet + validator candidate),
  siapkan 1 host, rehearsal di Devnet mode observer, lalu tunggu signed Testnet kit.
- **Miner:** rehearsal di Devnet pakai pack resmi (verifikasi sha256 dulu), jangan
  berharap stake Devnet ikut pindah ke Testnet.
- **Faucet:** 10 FLOP per wallet per 24 jam. Jangan retry penolakan, nonce sama
  idempoten, grant kedua butuh bukti spend.
- **Batas per-IP (paling sering bikin gagal):** 1 claim per IP per 24 jam
  (`ipCooldownSeconds: 86400`), dan tetangga di blok /24 yang sama berbagi jatah
  range (20/hari). **Beberapa agent di belakang satu IP publik tidak menambah
  jatah** — yang pertama mengklaim memblokir sisanya dengan `ip_cooldown`, walau
  tiap agent punya DID dan alamat sendiri yang sah.
- **`401` bukan tanda cooldown.** Body yang kurang/kunci salah ditolak sebelum
  sempat dicek IP-nya. Jalankan `faucet --check` dulu: dia memvalidasi alamat
  secara lokal tanpa mengirim apa pun.

Test FLOP = token uji tanpa nilai. Earning baru mulai di activation block resmi;
aktivitas sebelumnya 0 dan tanpa backfill.
