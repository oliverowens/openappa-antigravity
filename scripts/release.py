#!/usr/bin/env python3
"""
Release and Semantic Version Management Utility.

Automates test-driven version bumping, sanity checking, and release tagging for openappa-antigravity:
  python scripts/release.py --current
  python scripts/release.py --verify
  python scripts/release.py --bump auto
  python scripts/release.py --bump patch
  python scripts/release.py --bump minor
  python scripts/release.py --bump major
  python scripts/release.py --auto --tag --push
"""

from __future__ import annotations
import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent

VERSION_FILES = [
    ROOT_DIR / "pyproject.toml",
    ROOT_DIR / "appa-package.toml",
    ROOT_DIR / "runtime" / "__init__.py",
    ROOT_DIR / "adapter" / "__init__.py",
]

SEMVER_REGEX = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)


def get_current_version() -> str:
    pyproject = (ROOT_DIR / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'version\s*=\s*"([^"]+)"', pyproject)
    if not m:
        raise ValueError("Could not find version in pyproject.toml")
    return m.group(1)


def parse_semver(v: str) -> Tuple[int, int, int]:
    clean_v = v.strip().lstrip("v")
    if not SEMVER_REGEX.match(clean_v):
        raise ValueError(f"Version '{v}' does not strictly conform to Semantic Versioning (SemVer 2.0.0)")
    parts = clean_v.split("-")[0].split("+")[0].split(".")
    return int(parts[0]), int(parts[1]), int(parts[2])


def bump_version(current: str, part: str) -> str:
    major, minor, patch = parse_semver(current)
    if part == "major":
        return f"{major + 1}.0.0"
    elif part == "minor":
        return f"{major}.{minor + 1}.0"
    elif part == "patch":
        return f"{major}.{minor}.{patch + 1}"
    raise ValueError(f"Unknown bump part: '{part}'. Must be 'patch', 'minor', or 'major'")


def verify_versions() -> Tuple[bool, str, Dict[str, str]]:
    """
    Checks whether all package manifests, init files, and README badges are in lockstep.
    Returns (in_sync, primary_version, discrepancies_dict).
    """
    versions: Dict[str, str] = {}

    # 1. pyproject.toml
    pyproject = (ROOT_DIR / "pyproject.toml").read_text(encoding="utf-8")
    m1 = re.search(r'version\s*=\s*"([^"]+)"', pyproject)
    versions["pyproject.toml"] = m1.group(1) if m1 else "MISSING"

    # 2. appa-package.toml
    appa_pkg = (ROOT_DIR / "appa-package.toml").read_text(encoding="utf-8")
    m2 = re.search(r'version\s*=\s*"([^"]+)"', appa_pkg)
    versions["appa-package.toml"] = m2.group(1) if m2 else "MISSING"

    # 3. runtime/__init__.py
    rt_init = (ROOT_DIR / "runtime" / "__init__.py").read_text(encoding="utf-8")
    m3 = re.search(r'__version__\s*=\s*"([^"]+)"', rt_init)
    versions["runtime/__init__.py"] = m3.group(1) if m3 else "MISSING"

    # 4. adapter/__init__.py
    ad_init = (ROOT_DIR / "adapter" / "__init__.py").read_text(encoding="utf-8")
    m4 = re.search(r'__version__\s*=\s*"([^"]+)"', ad_init)
    versions["adapter/__init__.py"] = m4.group(1) if m4 else "MISSING"

    # 5. README.md badge
    readme = (ROOT_DIR / "README.md").read_text(encoding="utf-8")
    m5 = re.search(r'version-([0-9\.]+)-informational', readme)
    versions["README.md"] = m5.group(1) if m5 else "MISSING"

    primary = versions.get("pyproject.toml", "")
    discrepancies = {k: v for k, v in versions.items() if v != primary}
    return (len(discrepancies) == 0, primary, discrepancies)


def update_version_files(new_ver: str) -> None:
    # 1. pyproject.toml
    pyproject_path = ROOT_DIR / "pyproject.toml"
    content = pyproject_path.read_text(encoding="utf-8")
    content = re.sub(r'version\s*=\s*"[^"]+"', f'version = "{new_ver}"', content, count=1)
    pyproject_path.write_text(content, encoding="utf-8")

    # 2. appa-package.toml
    appa_pkg_path = ROOT_DIR / "appa-package.toml"
    if appa_pkg_path.exists():
        content = appa_pkg_path.read_text(encoding="utf-8")
        content = re.sub(r'version\s*=\s*"[^"]+"', f'version = "{new_ver}"', content, count=1)
        appa_pkg_path.write_text(content, encoding="utf-8")

    # 3. runtime/__init__.py
    rt_init = ROOT_DIR / "runtime" / "__init__.py"
    if rt_init.exists():
        rt_init.write_text(f'"""\nOpenAPPA Runtime package.\n"""\n\n__version__ = "{new_ver}"\n', encoding="utf-8")

    # 4. adapter/__init__.py
    ad_init = ROOT_DIR / "adapter" / "__init__.py"
    if ad_init.exists():
        ad_init.write_text(f'"""\nOpenAPPA Antigravity Adapter package.\n"""\n\n__version__ = "{new_ver}"\n', encoding="utf-8")

    # 5. README.md badge
    readme_path = ROOT_DIR / "README.md"
    if readme_path.exists():
        content = readme_path.read_text(encoding="utf-8")
        content = re.sub(r'version-[\d\.]+-informational', f'version-{new_ver}-informational', content, count=1)
        readme_path.write_text(content, encoding="utf-8")


def infer_bump_from_commits(commits: List[str]) -> Tuple[str, str]:
    """
    Infers semantic version bump ('patch', 'minor', 'major') from commit messages
    following Conventional Commits.
    Returns (bump_level, reason).
    """
    has_breaking = False
    breaking_reason = ""
    has_feature = False
    feature_reason = ""

    for msg in commits:
        lines = msg.strip().splitlines()
        first_line = lines[0] if lines else ""

        # Breaking change detection: feat!: or fix!: or BREAKING CHANGE: footer
        if re.search(r"^[a-zA-Z]+(\([^\)]+\))?!:", first_line):
            has_breaking = True
            breaking_reason = f"Breaking change detected in commit title: {first_line}"
            break
        for line in lines:
            if re.search(r"^BREAKING[-\s]CHANGE:\s*", line, re.IGNORECASE):
                has_breaking = True
                breaking_reason = f"Breaking change footer detected: {line}"
                break
        if has_breaking:
            break

        # Minor feature detection: feat: or feat(...):
        if re.search(r"^feat(\([^\)]+\))?:\s*", first_line):
            has_feature = True
            if not feature_reason:
                feature_reason = f"Feature detected: {first_line}"

    if has_breaking:
        return "major", breaking_reason
    if has_feature:
        return "minor", feature_reason
    return "patch", "Standard backward-compatible changes or bugfixes"


def get_commits_since_last_tag() -> List[str]:
    try:
        tag_proc = subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0"],
            cwd=ROOT_DIR,
            capture_output=True,
            text=True,
            check=True,
        )
        last_tag = tag_proc.stdout.strip()
        log_proc = subprocess.run(
            ["git", "log", f"{last_tag}..HEAD", "--format=%B%x00"],
            cwd=ROOT_DIR,
            capture_output=True,
            text=True,
            check=True,
        )
        return [c.strip() for c in log_proc.stdout.split("\x00") if c.strip()]
    except Exception:
        log_proc = subprocess.run(
            ["git", "log", "-n", "10", "--format=%B%x00"],
            cwd=ROOT_DIR,
            capture_output=True,
            text=True,
        )
        return [c.strip() for c in log_proc.stdout.split("\x00") if c.strip()]


def run_checks() -> bool:
    print("[Release] Running test-driven pre-release verification...")
    # 1. describe --check
    r1 = subprocess.run([sys.executable, "appa.py", "describe", "--check"], cwd=ROOT_DIR)
    if r1.returncode != 0:
        print("[ERROR] Policy check failed!", file=sys.stderr)
        return False

    # 2. replay
    r2 = subprocess.run([sys.executable, "appa.py", "replay", "policy-tests/"], cwd=ROOT_DIR)
    if r2.returncode != 0:
        print("[ERROR] Replay tests failed!", file=sys.stderr)
        return False

    # 3. unittest
    r3 = subprocess.run([sys.executable, "-m", "unittest", "tests/test_suite.py"], cwd=ROOT_DIR)
    if r3.returncode != 0:
        print("[ERROR] Unit tests failed!", file=sys.stderr)
        return False

    print("[Release] All pre-release verification checks PASSED.")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage openappa-antigravity semantic versioning and releases")
    parser.add_argument("version", nargs="?", help="Explicit new version (e.g. 0.4.1)")
    parser.add_argument("--current", action="store_true", help="Print current version and exit")
    parser.add_argument("--verify", action="store_true", help="Verify all package manifests are synchronized and SemVer compliant")
    parser.add_argument("--auto", action="store_true", help="Automatically infer bump level from git commit history")
    parser.add_argument("--bump", choices=["patch", "minor", "major", "auto"], help="Bump semantic version part")
    parser.add_argument("--tag", action="store_true", help="Create git tag (e.g. v0.4.1)")
    parser.add_argument("--push", action="store_true", help="Push commit and tag to git remote")
    parser.add_argument("--skip-checks", action="store_true", help="Skip pre-release tests")

    args = parser.parse_args()

    if args.verify:
        in_sync, primary, discrepancies = verify_versions()
        if in_sync:
            print(f"[SemVer Verify] SUCCESS: All manifests synchronized at v{primary}")
            sys.exit(0)
        else:
            print(f"[SemVer Verify] ERROR: Manifest version drift detected! Primary: {primary}", file=sys.stderr)
            for file, ver in discrepancies.items():
                print(f"  - {file}: {ver}", file=sys.stderr)
            sys.exit(1)

    curr = get_current_version()
    if args.current:
        print(f"Current version: {curr}")
        return

    bump_part = args.bump
    if args.auto or bump_part == "auto":
        commits = get_commits_since_last_tag()
        bump_part, reason = infer_bump_from_commits(commits)
        print(f"[Release] Auto-inferred SemVer bump '{bump_part}' ({reason}) across {len(commits)} commits.")

    if bump_part:
        target_version = bump_version(curr, bump_part)
    elif args.version:
        target_version = args.version
    else:
        parser.print_help()
        return

    # Validate target conforms to SemVer
    parse_semver(target_version)

    print(f"[Release] Upgrading version: {curr} -> {target_version}")

    if not args.skip_checks:
        if not run_checks():
            sys.exit(1)

    update_version_files(target_version)
    print(f"[Release] Updated version to {target_version} in all package manifests.")

    if args.tag or args.push:
        msg = f"Release v{target_version}"
        subprocess.run(["git", "add", "-A"], cwd=ROOT_DIR, check=True)
        subprocess.run(["git", "commit", "-m", msg], cwd=ROOT_DIR, check=False)
        tag_name = f"v{target_version}"
        subprocess.run(["git", "tag", "-a", tag_name, "-m", msg], cwd=ROOT_DIR, check=True)
        print(f"[Release] Created git tag {tag_name}")

        if args.push:
            subprocess.run(["git", "push", "origin", "main"], cwd=ROOT_DIR, check=True)
            subprocess.run(["git", "push", "origin", tag_name], cwd=ROOT_DIR, check=True)
            print(f"[Release] Pushed main and tag {tag_name} to origin!")


if __name__ == "__main__":
    main()
