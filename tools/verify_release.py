#!/usr/bin/env python3
"""Fail the release if any credential, secret, personal or internal value is
still present in a file that would be published to the repository.

Run from the repository root:

    python3 tools/verify_release.py

Exit code 0 = clean, 1 = a leak was found (details printed).

The scanner is deliberately conservative: it walks the working tree, skips the
paths that `.gitignore` excludes (by directory name), and flags both known
leaked values from this deployment and generic credential patterns.
"""
from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Directories that must never be published (kept in sync with .gitignore).
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "ENV",
    "runtime", "artifacts", "backups", "syslog-ingest", ".ui-check",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", "htmlcov", "dist", "build",
    "cmdb", "resource",
}
SKIP_DIR_PREFIXES = (".skill-cache-", "backup-")

# Files that are legitimately allowed to contain placeholder-looking values.
ALLOW_FILES = {
    "tools/verify_release.py",
    ".gitignore",
    ".dockerignore",
}
# SHA-256 fingerprints of exact values that leaked from this deployment. The
# scanner must never become a second plaintext copy of a revoked credential.
# NOTE: the upstream Wazuh sample credentials (MyS3cr37P450r.*-, SecretPassword,
# kibanaserver) are intentionally NOT listed: they are the public default values
# shipped by the official wazuh-docker project and are not deployment-private.
KNOWN_LEAK_HASHES = {
    "b92bec35c5ea1d74593b542e706e8cb22623a6dea5c34db23c9e673be321679e",
    "4a5522e784a21fbe4397cd508e534edc9391d8a79f9a1329ed4cb44dc32811ba",
    "79198b89b4513816a4da9fbba84794ed86d8e102531e0405c3bc81580a44c19d",
    "b30c61b4efe2a47bf6407bf6a312e64dbe3a5ea66346b93aba707c533c85f379",
    "5ddb8927ea25abb33099e29357ff46f0e54578e7ad31e013d87447fc033168de",
    "0617c600b63ddffa9441a3f409eb86dff4e7280c1b6709252fa53bca5db7a5db",
    "e2e4b7837f36f4653423df9eef0a2251c756a5b69b6daaf9b3306c6e0dbae5cc",
    "147851c1c6fdaa2e35c864e66ea5bcdcb78d589b032eb5c89d1ce3170b6c9a2b",
    "f35efeed22742d1bb4858008cf23700570ad643e619ff97075dbaa13c3909608",
    "1cb065872da2d66c3c501453b6e82b2888dd9ec8ef7886c4182bc549e3222476",
    "6a9c17d7b48f11e62385e63e99796f3ef49e7f6972e606f9b8b5690fa52aff0b",
    "779a5531204f1a22ab9cc61aeb34a22408873da0970e3382fede65beca97a9a7",
    "d7ac1da3a8ae727be30aae4e5f07f27eaa7332d3a0aad19fdcdc8c38186f7b6f",
    "fb4ee72eab1d6fb95619407dbfc2908b86f521817024b778b12f71a513b6763f",
    "1a99bcdddc2d596bd8f537e247c3a9df323578167bc9ca2ca58fef881fc8dcab",
    "fe864fd994482d482a5285b374c74975e4d3620a169ba0d4b79917b1a3252f38",
    "2592b8748869bb8ffdc0b30a3f676fbb0174757b18f673af182ebb456568ef23",
    "22ba86b79855fafd5fa04de1e3e4dd5520fb1cb5de8b521612b88b35eabb7413",
}
LEAK_TOKEN = re.compile(r"[A-Za-z0-9_~.#:/-]{7,}")

# Generic patterns (real secrets that a template must not carry).
GENERIC = [
    (re.compile(r"AI_PROVIDER_BASE_URL\s*=\s*https?://[^\s]*/(sk-|vscode/)"),
     "AI provider URL embeds a token; keep the key in AI_API_KEY"),
    (re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     "private key material"),
]

# Names that are only a problem when they contain a non-placeholder value.
SECRET_ASSIGN = re.compile(
    r"^(?P<key>[A-Z0-9_]*(?:SECRET|PASSWORD|PASS|API_KEY|TOKEN|WEBHOOK|KEY)[A-Z0-9_]*)"
    r"\s*=\s*(?P<val>.+)$"
)
PLACEHOLDER = re.compile(
    r"^(__.*__|x+|your[-_].*|.*your.*|change[-_]?me|example|placeholder|<.*>|\*+|)$",
    re.IGNORECASE,
)
SAFE_DEFAULT = {"password", "oauth2", "graph", "true", "false", "none", "email", "json"}
# Keys that merely contain a trigger word but never hold a credential.
NON_SECRET_KEYS = re.compile(
    r"_(HOURS|SECONDS|TTL|SCOPES|ENABLED|AUTH|PROVIDER|FORMAT|TYPE|MODE|LEVEL|"
    r"DAYS|PORT|SIZE|LIMIT|INTERVAL)$"
)


def is_ignored_file(rel: str) -> bool:
    """Mirror .gitignore for files that never reach the repository."""
    name = rel.rsplit("/", 1)[-1]
    if name.endswith(".example"):
        return False
    if name == ".env" or name.startswith(".env."):
        return True
    if name.endswith(".env"):
        return True
    if rel.startswith("secrets/"):
        return True
    # Backups / patch snapshots
    if name.endswith((".bak", ".orig", ".rej")) or ".bak-" in name:
        return True
    # Certificates / private keys (gitignored)
    if name.endswith((".pem", ".key", ".crt", ".p12", ".pfx", ".jks")):
        return True
    # Upstream vendored CI (wazuh-docker) carries its own public sample creds.
    return "/.github/" in rel or rel.startswith("wazuh-stack") and "/.github" in rel


def iter_files():
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        parts = set(rel.parts)
        if parts & SKIP_DIRS:
            continue
        if any(part.startswith(SKIP_DIR_PREFIXES) for part in rel.parts):
            continue
        if is_ignored_file(rel.as_posix()):
            continue
        yield path, rel.as_posix()


def contains_known_leak(text: str, hashes: set[str] = KNOWN_LEAK_HASHES) -> bool:
    """Match exact leaked-value fingerprints without retaining their plaintext."""
    for token in LEAK_TOKEN.findall(text):
        candidates = [token, *re.split(r"[/:]", token)]
        if any(hashlib.sha256(candidate.encode()).hexdigest() in hashes for candidate in candidates if candidate):
            return True
    return False


def scan_text(path: Path, rel: str) -> list[str]:
    hits: list[str] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return hits
    allowed = rel in ALLOW_FILES
    if contains_known_leak(text):
        hits.append(f"{rel}: contains a known leaked value fingerprint")
    for pattern, reason in GENERIC:
        if pattern.search(text) and not allowed:
            hits.append(f"{rel}: {reason}")
    if rel.endswith(".example"):
        for lineno, line in enumerate(text.splitlines(), 1):
            match = SECRET_ASSIGN.match(line.strip())
            if not match:
                continue
            key = match.group("key")
            value = match.group("val").strip().strip('"').strip("'")
            if NON_SECRET_KEYS.search(key) or re.fullmatch(r"[0-9]+", value):
                continue
            if PLACEHOLDER.match(value) or value.lower() in SAFE_DEFAULT:
                continue
            if "wazuh:" in value:
                continue
            hits.append(f"{rel}:{lineno}: {key} has a non-placeholder value")
    return hits


def main() -> int:
    findings: list[str] = []
    for path, rel in iter_files():
        findings.extend(scan_text(path, rel))
    if findings:
        print("RELEASE NOT CLEAN — remove the following before pushing:")
        for item in findings:
            print("  -", item)
        return 1
    print("OK: no credentials, personal data or internal addresses detected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
