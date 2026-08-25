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
import json
import os
import subprocess
import sys
import time
import urllib.request

API = "https://api.github.com"


def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


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
    """Push via token-embedded URL (works without gh)."""
    subprocess.run(["git", "init", "-b", branch], cwd=workdir, check=True, capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=workdir, check=True, capture_output=True)
    # Only commit if there are changes
    r = run(["git", "diff", "--cached", "--quiet"], check=False)
    if r.returncode != 0:
        subprocess.run(["git", "commit", "-m", f"Technocore contribution: {name}"],
                       cwd=workdir, check=True, capture_output=True)
    remote_url = f"https://x-access-token:{token}@github.com/{repo_full}.git"
    subprocess.run(["git", "remote", "remove", "origin"], cwd=workdir, check=False, capture_output=True)
    subprocess.run(["git", "remote", "add", "origin", remote_url], cwd=workdir, check=True, capture_output=True)
    subprocess.run(["git", "push", "-u", "origin", branch], cwd=workdir, check=True, capture_output=True)
    r = run(["git", "rev-parse", "HEAD"], check=False)
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
                rc = run(["git", "diff", "--cached", "--quiet"], check=False)
                if rc.returncode != 0:
                    subprocess.run(["git", "commit", "-m", f"Technocore contribution: {args.name}"],
                                   cwd=workdir, check=True, capture_output=True)
                subprocess.run(["git", "remote", "remove", "origin"], cwd=workdir, check=False, capture_output=True)
                subprocess.run(["git", "remote", "add", "origin",
                                f"https://github.com/{username}/{args.name}.git"],
                               cwd=workdir, check=True, capture_output=True)
                subprocess.run(["git", "push", "-u", "origin", branch], cwd=workdir, check=True, capture_output=True)
            commit = run(["git", "rev-parse", "HEAD"]).stdout.strip()
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
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
