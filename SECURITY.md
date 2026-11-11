# Security Policy

## Reporting a vulnerability

**Do not open a public GitHub issue for a security problem.** Instead,
contact the repository maintainer privately (see the profile of
[@zannyzette](https://github.com/zannyzette)) and describe the issue,
including steps to reproduce. The maintainer will acknowledge the report,
fix it, and credit the reporter if they wish.

If you find a secret (private key, passphrase, token) committed in this
repository's history, treat it as compromised: rotate it immediately and
tell the maintainer so the history can be purged.

## What this project protects

- `identity.pem` — an encrypted Ed25519 private key (PKCS8, file mode 0600).
  Losing it + the passphrase means losing the DID forever; leaking it means
  anyone can sign as your DID.
- The passphrase — the only thing protecting the key. There is **no
  recovery, no reset**. The script never stores the passphrase.
- `GITHUB_TOKEN` — a GitHub credential. It is never written to `.git/config`
  or printed in logs by `github_upload.py` (one-shot `GIT_ASKPASS` only).

## Rules for operators

1. **Never commit `identity.pem`, `passphrase.txt`, `.env`, or any `*.pem` /
   `*.key` file.** `github_upload.py` refuses to stage them, but the guard
   cannot recognise every possible secret filename — keep secrets out of
   upload folders entirely.
2. **Never share your private key or passphrase with anyone or any agent.**
   An agent that applies patches, runs tests, or reviews code does not need
   your key. If a tool or person asks for it, refuse.
3. **A `GITHUB_TOKEN` that was ever used with the pre-1.2.0
   `push_with_token` must be treated as leaked** — that version embedded the
   token in the git remote URL stored in `.git/config`. Revoke/rotate it on
   GitHub and check `.git/config` in every folder you ever uploaded from.
4. **Proofs are v2 only.** v1 proofs (`technocore-contribution-proof-v1`,
   payload `url|commit`) no longer verify — they bound nothing but a string
   and could be replayed forever. Re-issue proofs with `proof` after
   upgrading; a v2 proof expires after 90 days.
5. **DID rotation history.** This repository's DID has changed three times
   in the past, and the old rotations were recorded only as plaintext
   strings — they cannot be cryptographically linked retroactively (the old
   keys are not in this repo and must never be shared). From v1.2.0 onward,
   use `rotate`: it creates a new identity and a rotation statement signed
   by the OLD key, so verifiers can follow old DID → new DID. Publish each
   rotation statement (commit it + announce it in your room).
6. **tclk/1 deals.** A `tclk1 {…}` frame is a signed room message on the
   same signing lane as `say`. Compromise of one key = ability to forge
   deals. The settlement rails are unaudited rehearsal code — do not put
   real value behind them.

## Supported versions

Only the latest release on `main` is supported. Older versions — in
particular anything before 1.2.0 — contain the vulnerabilities fixed in
the 2026-11-11 security audit (see CHANGELOG.md) and should be upgraded.
