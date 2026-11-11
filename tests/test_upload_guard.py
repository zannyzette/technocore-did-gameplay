"""github_upload.py: secret guard, protective .gitignore, token handling, cwd."""
import os
import subprocess

import pytest

import github_upload as gu


def git(*args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture(autouse=True)
def _git_identity(monkeypatch):
    # Fresh tmp repos have no git identity configured; without this every
    # `git commit` in the tests fails with exit 128.
    monkeypatch.setenv("GIT_AUTHOR_NAME", "Test")
    monkeypatch.setenv("GIT_AUTHOR_EMAIL", "test@example.com")
    monkeypatch.setenv("GIT_COMMITTER_NAME", "Test")
    monkeypatch.setenv("GIT_COMMITTER_EMAIL", "test@example.com")


def init_repo(path, head_file="README.md"):
    path.mkdir(parents=True, exist_ok=True)
    git("init", "-b", "main", cwd=str(path))
    git("config", "user.email", "test@example.com", cwd=str(path))
    git("config", "user.name", "Test", cwd=str(path))
    (path / head_file).write_text("hello\n", encoding="utf-8")
    git("add", "-A", cwd=str(path))
    git("commit", "-m", "init", cwd=str(path))


@pytest.mark.parametrize("relpath,secret", [
    ("identity.pem", True),
    ("sub/identity.pem", True),
    ("passphrase.txt", True),
    ("passphrase-backup", True),
    ("id_rsa", True),
    ("id_ed25519", True),
    ("id_ecdsa.pub", False),   # .pub halves are public by definition
    ("github_token.txt", True),
    ("token.txt", True),
    ("mysecret.txt", True),
    (".aws/credentials", True),
    (".ssh/id_ed25519", True),
    (".env", True),
    (".env.local", True),
    ("foo.pem", True),
    ("foo.key", True),
    ("foo.token", True),
    ("README.md", False),
    ("proof.json", False),
    ("config.json", False),   # too generic to block — documented limitation
    ("token.md", False),
    ("src/tokenizer.py", False),
    ("notes.txt", False),
])
def test_is_secret_path(relpath, secret):
    assert gu.is_secret_path(relpath) is secret


def test_stage_refuses_identity_and_passphrase_in_fresh_dir(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    (work / "identity.pem").write_text("FAKE-PEM", encoding="utf-8")
    (work / "passphrase.txt").write_text("secret", encoding="utf-8")
    (work / "README.md").write_text("hi\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="refusing to upload: secret file"):
        gu.stage_and_commit(str(work), "demo", "main")
    # Nothing staged after the refusal (guard resets the index).
    r = subprocess.run(["git", "diff", "--cached", "--name-only"],
                       cwd=str(work), capture_output=True, text=True)
    assert r.stdout.strip() == ""


def test_stage_refuses_ssh_key_and_token(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    (work / "id_ed25519").write_text("FAKE", encoding="utf-8")
    (work / "github_token.txt").write_text("ghp_fake", encoding="utf-8")
    (work / "README.md").write_text("hi\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="refusing to upload: secret file"):
        gu.stage_and_commit(str(work), "demo", "main")


def test_staged_gate_catches_forced_secrets(tmp_path):
    # Second layer: a secret staged with `git add -f` (bypassing .gitignore)
    # is caught by the post-add gate, which also resets the index.
    work = tmp_path / "work"
    init_repo(work)
    (work / "passphrase.txt").write_text("secret", encoding="utf-8")
    git("add", "-f", "passphrase.txt", cwd=str(work))
    with pytest.raises(RuntimeError, match="refusing to commit secret"):
        gu.check_staged_secrets(str(work))
    r = subprocess.run(["git", "diff", "--cached", "--name-only"],
                       cwd=str(work), capture_output=True, text=True)
    assert r.stdout.strip() == ""


def test_protective_gitignore_written_when_missing(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    (work / "README.md").write_text("hi\n", encoding="utf-8")
    gu.stage_and_commit(str(work), "demo", "main")
    assert (work / ".gitignore").exists()
    assert "identity.pem" in (work / ".gitignore").read_text(encoding="utf-8")
    # Second run does not duplicate the block.
    gu.stage_and_commit(str(work), "demo", "main")
    text = (work / ".gitignore").read_text(encoding="utf-8")
    assert text.count(gu.PROTECTIVE_GITIGNORE_MARKER) == 1


def test_clean_dir_stages_and_commits(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    (work / "README.md").write_text("hi\n", encoding="utf-8")
    gu.stage_and_commit(str(work), "demo", "main")
    r = subprocess.run(["git", "log", "--oneline"], cwd=str(work),
                       capture_output=True, text=True)
    assert "Technocore contribution: demo" in r.stdout


def test_tracked_secret_refused(tmp_path):
    work = tmp_path / "work"
    init_repo(work)
    # Force-track a secret (simulating the old behaviour) — .gitignore
    # must NOT save it.
    (work / "passphrase.txt").write_text("secret", encoding="utf-8")
    git("add", "-f", "passphrase.txt", cwd=str(work))
    git("commit", "-m", "oops", cwd=str(work))
    (work / "README.md").write_text("changed\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="already tracked"):
        gu.stage_and_commit(str(work), "demo", "main")


def test_run_respects_cwd(tmp_path):
    repo_a = tmp_path / "a"
    repo_b = tmp_path / "b"
    init_repo(repo_a)
    init_repo(repo_b)
    (repo_b / "README.md").write_text("different\n", encoding="utf-8")
    git("add", "-A", cwd=str(repo_b))
    git("commit", "-m", "second", cwd=str(repo_b))
    head_a = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(repo_a),
                            capture_output=True, text=True).stdout.strip()
    head_b = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(repo_b),
                            capture_output=True, text=True).stdout.strip()
    assert head_a != head_b
    # run() from repo_a's cwd must return repo_b's HEAD when cwd=repo_b.
    out = gu.run(["git", "rev-parse", "HEAD"], cwd=str(repo_b)).stdout.strip()
    assert out == head_b


def test_redact_removes_token():
    token = "ghp_DUMMYTOKEN1234567890"
    text = f"Command '['git', 'remote', 'add', 'origin', 'https://x-access-token:{token}@github.com/x/y.git']' failed"
    redacted = gu._redact(text, token)
    assert token not in redacted
    assert "https://***@github.com/x/y.git" in redacted


class _FakeRun:
    """Fake subprocess.run: records calls, pretends git works."""

    def __init__(self):
        self.calls = []

    def __call__(self, cmd, **kwargs):
        self.calls.append((cmd, kwargs))
        if cmd[:3] == ["git", "diff", "--cached"]:
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")
        if cmd[:2] == ["git", "remote"] and cmd[2] == "get-url":
            return subprocess.CompletedProcess(cmd, 0, stdout="https://github.com/u/r.git\n", stderr="")
        if cmd[:2] == ["git", "rev-parse"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="abc123\n", stderr="")
        if cmd[:2] == ["git", "ls-files"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")


def test_push_with_token_never_persists_token(tmp_path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir()
    (work / "README.md").write_text("hi\n", encoding="utf-8")
    fake = _FakeRun()
    monkeypatch.setattr(gu.subprocess, "run", fake)
    token = "ghp_DUMMYTOKEN1234567890"
    commit = gu.push_with_token(token, "user/repo", "repo", "main", str(work))
    assert commit == "abc123"
    # No argv anywhere contains the token.
    for cmd, kwargs in fake.calls:
        assert not any(token in str(a) for a in cmd), f"token leaked into argv: {cmd}"
        env = kwargs.get("env") or {}
        assert token not in str(env.get("GIT_ASKPASS", ""))
    # The remote URL set is the clean one, and set-url restores it after push.
    remote_adds = [c for c, _ in fake.calls if c[:3] == ["git", "remote", "add"]]
    assert remote_adds and remote_adds[0][4] == "https://github.com/user/repo.git"
    # The push itself used the one-shot askpass helper, not a URL.
    push_calls = [kw for c, kw in fake.calls if c[:2] == ["git", "push"]]
    assert push_calls and "GIT_ASKPASS" in (push_calls[0].get("env") or {})
    assert push_calls[0]["env"]["GH_ASKPASS_TOKEN"] == token
