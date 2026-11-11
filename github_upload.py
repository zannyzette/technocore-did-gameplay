#!/usr/bin/env python3
"""
GitHub auto-upload helper for Technocore contributions.

Creates a public (or private) repository, uploads the current directory's
files, and prints the repo URL + latest commit hash — ready to be signed
into a contribution proof.

Requirements: the `gh` CLI authenticated (`gh auth login`), or a GitHub
personal access token in the GITHUB_TOKEN environment variable.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

API = "https://api.github.com"

# Names/patterns that must never be committed from an arbitrary upload dir.
SECRET_NAMES = {"identity.pem", "passphrase.txt", "passphrase", "credentials", "id_rsa", "id_ed25519"}
SECRET_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".token")
SECRET_DIRS = (".aws/", ".ssh/", ".gnupg/")


def run(cmd: list[str], check: bool = True, cwd: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check, cwd=cwd)


def redact(text: str) -> str:
    """Strip anything that looks like a token from text before printing it."""
    text = re.sub(r"https://[^@\s]+@", "https://<redacted>@", text)
    return re.sub(r"\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{8,}", "<redacted-token>", text)


def staged_secrets(workdir: str) -> list[str]:
    """Return staged paths that look like credentials. Empty list = safe to commit."""
    r = run(["git", "diff", "--cached", "--name-only"], check=False, cwd=workdir)
    bad = []
    for path in r.stdout.splitlines():
        path = path.strip()
        if not path:
            continue
        low = path.lower()
        base = os.path.basename(low)
        if base in SECRET_NAMES or low.endswith(SECRET_SUFFIXES):
            bad.append(path)
        elif any(low.startswith(d) or f"/{d}" in low for d in SECRET_DIRS):
            bad.append(path)
    return bad


def guard_staged(workdir: str) -> None:
    bad = staged_secrets(workdir)
    if bad:
        raise RuntimeError(
            "refusing to commit: staged files look like credentials: "
            + ", ".join(bad)
            + " — move them out of the upload dir or add them to .gitignore"
        )


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
        detail = e.read().decode()[:200]
        if e.code == 422 and "already exists" in detail:
            return None  # repo exists — push to it
        raise RuntimeError(f"create repo failed ({e.code}): {detail}")


def push_with_token(token: str, repo_full: str, name: str, branch: str, workdir: str) -> str:
    """Push using a one-shot auth header — the token never lands in .git/config."""
    subprocess.run(["git", "init", "-b", branch], cwd=workdir, check=True, capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=workdir, check=True, capture_output=True)
    guard_staged(workdir)
    # Only commit if there are changes
    r = run(["git", "diff", "--cached", "--quiet"], check=False, cwd=workdir)
    if r.returncode != 0:
        subprocess.run(["git", "commit", "-m", f"Technocore contribution: {name}"],
                       cwd=workdir, check=True, capture_output=True)
    clean_url = f"https://github.com/{repo_full}.git"
    # base64("x-access-token:<token>") as a Basic auth header, passed via -c so it is
    # never written to .git/config and never appears in argv of a persisted remote.
    basic = base64.b64encode(("x-access-" + "token:" + token).encode()).decode()
    subprocess.run(["git", "remote", "remove", "origin"], cwd=workdir, check=False, capture_output=True)
    subprocess.run(["git", "remote", "add", "origin", clean_url], cwd=workdir, check=True, capture_output=True)
    subprocess.run(["git", "-c", "http.extraHeader=AUTHORIZATION: basic " + basic,
                    "push", "-u", "origin", branch],
                   cwd=workdir, check=True, capture_output=True)
    r = run(["git", "rev-parse", "HEAD"], check=False, cwd=workdir)
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

    try:
        token = os.environ.get("GITHUB_TOKEN", "")
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
                subprocess.run(["git", "init", "-b", branch], cwd=workdir, check=True, capture_output=True)
                subprocess.run(["git", "add", "-A"], cwd=workdir, check=True, capture_output=True)
                guard_staged(workdir)
                rc = run(["git", "diff", "--cached", "--quiet"], check=False, cwd=workdir)
                if rc.returncode != 0:
                    subprocess.run(["git", "commit", "-m", f"Technocore contribution: {args.name}"],
                                   cwd=workdir, check=True, capture_output=True)
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
        print(f"error: {redact(str(e))}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
