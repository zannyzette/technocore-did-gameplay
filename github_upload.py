#!/usr/bin/env python3
"""
GitHub auto-upload helper for Technocore contributions.

Creates a public (or private) repository, uploads the current directory's
files, and prints the repo URL + latest commit hash — ready to be signed
into a contribution proof.

Requirements: the `gh` CLI authenticated (`gh auth login`), or a GitHub
personal access token in the GITHUB_TOKEN environment variable.

Security (see SECURITY.md):
  * BEFORE any `git add`, this script writes a protective .gitignore into
    the workdir (if the patterns are missing) and REFUSES to stage known
    secret files (identity.pem, passphrase*, *.pem, *.key, id_rsa*,
    id_ed25519*, *.token, .env*, .aws/credentials, .ssh/*, ...). A secret
    that is already tracked is also refused — .gitignore never protects
    tracked files, so check with `git ls-files` before pushing.
  * GITHUB_TOKEN is NEVER embedded in a remote URL and NEVER stored in
    .git/config. Pushes use a one-shot GIT_ASKPASS helper whose token lives
    only in the child process environment and is deleted afterwards; the
    remote is always restored to the clean https://github.com/... URL.
  * Errors are redacted: a token never appears in printed output.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.request

API = "https://api.github.com"

# ---------------------------------------------------------------------------
# Secret guard
# ---------------------------------------------------------------------------

# Basenames that are always secrets, whatever directory they sit in.
SECRET_BASENAMES = frozenset({
    "identity.pem",
    ".env",
    ".git-credentials",
    "hosts.yml",
    "credentials",
    "token.txt",
    "github_token.txt",
    "seed.txt",
    "seedphrase.txt",
    "deploy_key",
    "deploy_key.pem",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "wallet.json",
    "keystore.json",
})
# Basenames that start with one of these prefixes are secrets.
SECRET_BASENAME_PREFIXES = (
    "passphrase",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_ed448",
    ".env.",
)
# Suffixes that mark a file as a key/token.
SECRET_SUFFIXES = (".pem", ".key", ".token", ".p12", ".pfx")
# Any path component in this set marks the file as a credential store.
SECRET_PATH_PARTS = frozenset({".aws", ".ssh", ".gnupg"})
# Basenames containing "secret"/"token" with a data-file suffix.
SECRET_WORD_SUFFIXES = (".txt", ".json", ".yaml", ".yml", ".ini", ".cfg")

# Public files that LOOK like secrets but are meant to be committed.
# Templates carry no real value; .pub halves are public by definition.
TEMPLATE_SUFFIXES = (
    ".example", ".sample", ".template", ".tmpl", ".dist", ".defaults",
)
PUBLIC_SUFFIXES = (".pub", ".example", ".sample", ".template", ".dist")


# Patterns appended to a workdir .gitignore so plain `git add` in other
# tools does not pick these up either. (The hard guard below is what
# actually enforces it — .gitignore alone never protects tracked files.)
PROTECTIVE_GITIGNORE = """\
# --- added by github_upload.py: never commit secrets ---
identity.pem
*.pem
*.key
passphrase*
*.secret
*secret*.txt
*secret*.json
id_rsa*
id_ed25519*
id_ecdsa*
id_ed448*
*.token
*token*.txt
.p12
.pfx
.npmrc
.pypirc
.netrc
wallet.json
keystore.json
seed.txt
seedphrase.txt
deploy_key
.env
.env.*
credentials
credentials*
.aws/
.ssh/
.gnupg/
.git-credentials
hosts.yml

# ...but templates and public halves are meant to be committed.
!.env.example
!.env.sample
!.env.template
!.env.dist
!*.pub
!*credentials.example
"""
PROTECTIVE_GITIGNORE_MARKER = "# --- added by github_upload.py"


def is_secret_path(relpath: str) -> bool:
    """True if a repo-relative path looks like a secret/credential file.

    Public-by-design files win first: `.env.example`, `id_rsa.pub` and other
    template/public halves are meant to be committed, so they never trip the
    guard. Everything else that looks like a credential does.
    """
    parts = relpath.replace("\\", "/").split("/")
    name = parts[-1]
    lower = name.lower()

    # Templates and public key halves are safe to publish.
    if lower.endswith(PUBLIC_SUFFIXES):
        return False

    if name in SECRET_BASENAMES:
        return True
    if lower == "credentials" or lower.startswith("credentials."):
        return True
    if lower.startswith(SECRET_BASENAME_PREFIXES):
        return True
    if lower.endswith(SECRET_SUFFIXES):
        return True
    if any(part in SECRET_PATH_PARTS for part in parts):
        return True
    if "secret" in lower and lower.endswith(SECRET_WORD_SUFFIXES):
        return True
    if "token" in lower and lower.endswith((".txt", ".json")):
        return True
    return False


def ensure_protective_gitignore(workdir: str) -> None:
    """Make sure the workdir .gitignore covers the secret patterns.

    Writes a new .gitignore if there is none; appends the protective block
    (once, guarded by its marker comment) if one exists without it.
    """
    path = os.path.join(workdir, ".gitignore")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            existing = f.read()
        if PROTECTIVE_GITIGNORE_MARKER in existing:
            return
        with open(path, "a", encoding="utf-8") as f:
            f.write("\n" + PROTECTIVE_GITIGNORE)
    else:
        with open(path, "w", encoding="utf-8") as f:
            f.write(PROTECTIVE_GITIGNORE)


def check_no_tracked_secrets(workdir: str) -> None:
    """Refuse if a secret file is already tracked (git ls-files).

    .gitignore does not apply to tracked files, so this is a separate gate.
    """
    r = run(["git", "ls-files"], cwd=workdir, check=False)
    if r.returncode != 0:
        return  # not a git repo (yet) — nothing tracked
    bad = [p for p in r.stdout.splitlines() if is_secret_path(p.strip())]
    if bad:
        raise RuntimeError(
            "refusing to upload: secret file(s) already tracked in git: "
            + ", ".join(bad)
            + " — remove them with `git rm --cached <file>` (and purge them "
              "from history if they were ever pushed) before uploading"
        )


def check_workdir_for_secrets(workdir: str) -> None:
    """Refuse if a secret-pattern file exists anywhere in the workdir.

    This runs BEFORE `git add`, so the guard does not depend on .gitignore
    being correct — a fresh folder with identity.pem + passphrase.txt next
    to the contribution is refused outright, even though the protective
    .gitignore would also have hidden them.
    """
    skip_dirs = {".git", ".venv", "venv", "__pycache__", "node_modules"}
    bad = []
    for root, dirs, files in os.walk(workdir):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for name in files:
            rel = os.path.relpath(os.path.join(root, name), workdir)
            if is_secret_path(rel):
                bad.append(rel)
    if bad:
        raise RuntimeError(
            "refusing to upload: secret file(s) in upload folder: "
            + ", ".join(sorted(bad))
            + " — move them out of this folder (never upload a folder that "
              "contains your identity or tokens) and try again"
        )


def check_staged_secrets(workdir: str) -> None:
    """Refuse if any secret file is staged after `git add`."""
    r = run(["git", "diff", "--cached", "--name-only"], cwd=workdir, check=False)
    bad = [p for p in r.stdout.splitlines() if is_secret_path(p.strip())]
    if bad:
        run(["git", "reset"], cwd=workdir, check=False)
        raise RuntimeError(
            "refusing to commit secret file(s): " + ", ".join(bad)
            + " — remove them from the directory (or move them out of the "
              "upload folder) and try again"
        )


def stage_and_commit(workdir: str, name: str, branch: str) -> None:
    """git add -A with the secret guard, then commit if anything changed."""
    ensure_protective_gitignore(workdir)
    check_no_tracked_secrets(workdir)
    check_workdir_for_secrets(workdir)
    subprocess.run(["git", "init", "-b", branch], cwd=workdir, check=True, capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=workdir, check=True, capture_output=True)
    check_staged_secrets(workdir)
    r = run(["git", "diff", "--cached", "--quiet"], cwd=workdir, check=False)
    if r.returncode != 0:
        subprocess.run(["git", "commit", "-m", f"Technocore contribution: {name}"],
                       cwd=workdir, check=True, capture_output=True)


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------


def run(cmd: list[str], check: bool = True, cwd: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check, cwd=cwd)


def _redact(text: str, token: str | None = None) -> str:
    """Remove a token (and any token-embedded URL) from text before printing."""
    # Token-embedded URLs first: the raw-token replace below would otherwise
    # leave a mangled (but still recognisable) fragment behind.
    text = re.sub(r"https://x-access-token:[^@\s]+@", "https://x-access-token:***@", text)
    text = re.sub(r"https://[^:\s]+:[^@\s]+@github\.com", "https://***@github.com", text)
    if token:
        text = text.replace(token, "***REDACTED***")
    return text


def have_gh() -> bool:
    try:
        r = run(["gh", "--version"], check=False)
        return r.returncode == 0
    except FileNotFoundError:
        return False


def gh_username() -> str:
    r = run(["gh", "api", "user", "--jq", ".login"])
    if r.returncode != 0:
        raise RuntimeError("gh not authenticated — run 'gh auth login'")
    return r.stdout.strip()


def token_username(token: str) -> str:
    req = urllib.request.Request(API + "/user", headers={
        "Authorization": f"Bearer {token}",
        "User-Agent": "technocore-upload",
        "Accept": "application/vnd.github+json",
    })
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read())["login"]


def create_repo_api(token: str, name: str, private: bool, description: str) -> str:
    body = json.dumps({
        "name": name,
        "private": private,
        "description": description,
        "auto_init": False,
    }).encode()
    req = urllib.request.Request(API + "/user/repos", data=body, method="POST", headers={
        "Authorization": f"Bearer {token}",
        "User-Agent": "technocore-upload",
        "Content-Type": "application/json",
        "Accept": "application/vnd.github+json",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())["full_name"]
    except urllib.error.HTTPError as e:
        detail = e.read(200).decode(errors="replace")
        if e.code == 422 and "already exists" in detail:
            return None  # repo exists — push to it
        raise RuntimeError(f"create repo failed ({e.code}): {detail}")


def _push_with_askpass(workdir: str, branch: str, token: str) -> None:
    """Push over HTTPS with a one-shot GIT_ASKPASS helper.

    The token lives only in the child process environment (never in argv,
    never in .git/config, never in a file). The helper script is created
    with mode 0700 and deleted in a finally block.
    """
    tmpdir = tempfile.mkdtemp(prefix="gh-askpass-")
    try:
        script = os.path.join(tmpdir, "askpass.sh")
        with open(script, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\nprintf '%s\\n' \"$GH_ASKPASS_TOKEN\"\n")
        os.chmod(script, 0o700)
        env = dict(os.environ)
        env["GIT_ASKPASS"] = script
        env["GH_ASKPASS_TOKEN"] = token
        env["GIT_TERMINAL_PROMPT"] = "0"
        subprocess.run(["git", "push", "-u", "origin", branch],
                       cwd=workdir, check=True, capture_output=True, env=env)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def push_with_token(token: str, repo_full: str, name: str, branch: str, workdir: str) -> str:
    """Push via GITHUB_TOKEN without ever persisting it in .git/config."""
    stage_and_commit(workdir, name, branch)
    clean_url = f"https://github.com/{repo_full}.git"
    subprocess.run(["git", "remote", "remove", "origin"], cwd=workdir, check=False, capture_output=True)
    subprocess.run(["git", "remote", "add", "origin", clean_url], cwd=workdir, check=True, capture_output=True)
    try:
        _push_with_askpass(workdir, branch, token)
    finally:
        # Always restore the clean remote URL, even if the push failed.
        subprocess.run(["git", "remote", "set-url", "origin", clean_url],
                       cwd=workdir, check=False, capture_output=True)
    r = run(["git", "remote", "get-url", "origin"], cwd=workdir, check=False)
    if token in r.stdout or "x-access-token" in r.stdout:
        raise RuntimeError("refusing to leave a token in the git remote URL")
    r = run(["git", "rev-parse", "HEAD"], cwd=workdir, check=False)
    return r.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Auto-upload a Technocore contribution to GitHub.")
    parser.add_argument("name", help="repository name (e.g. technocore-did-gameplay)")
    parser.add_argument("--private", action="store_true", help="create a private repo (default: public)")
    parser.add_argument("--description", default="Technocore DID contribution", help="repo description")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--dir", default=".", help="directory to upload (default: current)")
    args = parser.parse_args()

    workdir = os.path.abspath(args.dir)
    branch = args.branch
    token = os.environ.get("GITHUB_TOKEN", "")

    try:
        # Secret guard first: it applies to every auth path below,
        # including `gh repo create --source --push`, which stages files
        # itself and would otherwise bypass stage_and_commit.
        ensure_protective_gitignore(workdir)
        check_no_tracked_secrets(workdir)
        check_workdir_for_secrets(workdir)

        if have_gh():
            username = gh_username()
            # Create repo with gh
            vis = "private" if args.private else "public"
            r = run(["gh", "repo", "create", args.name, f"--{vis}", "--source", workdir,
                     "--description", args.description, "--push"], check=False)
            if r.returncode != 0:
                # Repo may already exist — push to it directly
                r = run(["gh", "repo", "view", f"{username}/{args.name}"], check=False)
                if r.returncode != 0:
                    raise RuntimeError("gh repo create failed")
                stage_and_commit(workdir, args.name, branch)
                subprocess.run(["git", "remote", "remove", "origin"], cwd=workdir, check=False, capture_output=True)
                subprocess.run(["git", "remote", "add", "origin",
                                f"https://github.com/{username}/{args.name}.git"],
                               cwd=workdir, check=True, capture_output=True)
                subprocess.run(["git", "push", "-u", "origin", branch], cwd=workdir, check=True, capture_output=True)
            commit = run(["git", "rev-parse", "HEAD"], cwd=workdir).stdout.strip()
            print(f"repo:    https://github.com/{username}/{args.name}")
            print(f"commit:  {commit}")
            return 0

        if token:
            username = token_username(token)
            full = create_repo_api(token, args.name, args.private, args.description)
            if full is None:
                full = f"{username}/{args.name}"
            commit = push_with_token(token, full, args.name, branch, workdir)
            print(f"repo:    https://github.com/{full}")
            print(f"commit:  {commit}")
            return 0

        print("no auth found: install/authenticate `gh` (gh auth login) or set GITHUB_TOKEN", file=sys.stderr)
        return 1
    except Exception as e:
        # Never print argv (a CalledProcessError str() includes the full
        # command line) or a raw token.
        print(f"error: {_redact(str(e), token)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
