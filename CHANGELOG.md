# Changelog

## 1.2.1 — 2026-11-12 (review of the 1.2.0 patch)

Closes 7 gaps found while reviewing the 1.2.0 security patch. 118 tests pass.

### Fixed
- **`init` refuses to create a SECOND identity.** Before, running `init` while an
  identity already existed (in `~/.technocore/` or as `./identity.pem`) silently
  minted a new key that then shadowed the old one — every later `say`/`proof`
  would sign as the wrong DID with no error. Now it errors and points at
  `rotate`. This was the most damaging remaining failure mode: a second `init`
  is indistinguishable from "losing" your DID.
- **`.env.example` and other templates are no longer blocked** by the secret
  guard, and `*.pub` halves are allowed (they are public by design). The
  protective `.gitignore` gained matching `!` negations so templates stay
  committable.
- **`rotation.json` / `revocation.json` are no longer gitignored.** 1.2.0 told
  you to commit them in `SECURITY.md` and in the CLI output while `.gitignore`
  silently hid them.
- **Proof host allowlist widened** to match what the README promises
  ("a repo, an X thread, a video, an article"): gitlab, codeberg, bitbucket,
  medium, dev.to, substack, youtube, vimeo, mirror.xyz, hackmd, notion.site.
  Extra hosts can be added without editing code:
  `TECHNOCORE_PROOF_HOSTS="example.com,blog.example.org"`.
- **Secret guard extended**: `credentials.*`, `wallet.json`, `keystore.json`,
  `seed.txt`, `seedphrase.txt`, `deploy_key`, `.npmrc`, `.pypirc`, `.netrc`,
  `*.p12`, `*.pfx`, `.gnupg/`.
- **Proof nonce accepts hex AND base64url.** Both encode the same 16 random
  bytes and carry >=128 bits; the hex-only check rejected proofs produced by
  other implementations of the same v2 schema.

### Added
- 43 regression tests (`tests/test_review_gaps.py`) covering all of the above.

## 1.2.0 — 2026-11-12 (security audit fixes)

Fixes all 13 findings of the 2026-11-11 read-only security audit
(1 Critical, 5 High, 4 Medium, 3 Low). All fixes were verified by re-running
every audit PoC against the fixed code — see `VERIFY.md` in the fix package.

### Breaking changes
- **Contribution proofs are now v2** (`technocore-contribution-proof-v2`).
  v1 proofs no longer verify. Re-issue `proof.json` with the `proof` command
  after upgrading (see APPLY.md in the fix package).
- **Default identity location is now `~/.technocore/identity.pem`.**
  A `./identity.pem` in the working directory is still honoured with a
  deprecation warning. Pass `--key` to use another location.

### Fixed
- `github_upload.py` now refuses to stage/commit secret files in ANY
  workdir (hard guard + protective `.gitignore`), and refuses already-tracked
  secrets.
- `GITHUB_TOKEN` is never embedded in a remote URL or stored in
  `.git/config`; pushes use a one-shot `GIT_ASKPASS` helper and the remote
  is always restored to the clean URL. Errors are redacted.
- `run()` in `github_upload.py` takes `cwd` and every git call passes
  `cwd=workdir`.
- `create_identity` passphrase confirmation now actually prompts and
  compares (was dead code).
- Passphrase files are read with `rstrip("\r\n")` only — passphrases with
  leading/trailing spaces no longer break silently.
- Proof v2 binds `schema|artifact_url|commit|issued_at|expires_at|nonce`
  (random nonce, 90-day expiry); verify validates schema, https + host
  allowlist, no userinfo, signature pattern, and expiry.
- `_request` caps response bodies at 1 MB, validates Content-Type, refuses
  cross-host redirects, and turns bad JSON into a clean `NetworkError`.
- `main()` returns clean errors instead of raw tracebacks; unencrypted PEM
  keys are refused; DIDs over 100 chars are rejected before base58 decode;
  `read` validates `limit` (1–200) and `since` (>= 0).
- README contradiction fixed: the script never stores the passphrase, but
  `--passphrase-file` IS plaintext on disk at the operator's risk.
- New commands: `rotate` / `verify-rotation`, `revoke` /
  `verify-revocation` (rotation statements signed by the old key).
- `cryptography` pinned (`>=42.0,<51` + `requirements.lock`); tests +
  CI added; `SECURITY.md` added.
