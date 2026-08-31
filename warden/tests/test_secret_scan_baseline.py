"""warden/tests/test_secret_scan_baseline.py

`.gitleaksignore` silences the full-history secret scan. Guard what it silences.

The scan in `.github/workflows/secret-history-scan.yml` re-reads every reachable
commit. Its first run found 22 matches, all triaged as documentation
placeholders, frontend identifiers or test fixtures — and then the job failed
every run, forever. A guard that is permanently red reports nothing: a 23rd
finding, this time a live credential, would look exactly like the 22.

Pinning the known matches is what lets the job say "something changed". But an
ignore file is a suppression mechanism, and the whole value of the baseline
rests on it being unable to cover anything it was not pointed at. These tests
pin that property:

  * Every entry is `commit:path:rule:line` with a full 40-hex SHA. It matches
    one blob at one line of one commit. A new secret arrives in a new commit,
    so it gets a new fingerprint, so nothing here covers it.
  * No globs. `*` or a bare path would silence a file's whole future.
  * The count is a stated baseline, so growing it is a reviewed act rather
    than a paste of a scan's output.
  * `.gitleaks.toml` grows no catch-all allowlist behind the baseline's back.
  * LF endings. A trailing CR makes every fingerprint miss and the scan stays
    red for reasons nobody can see — this was a real bug in the change that
    introduced the file.
  * The comments do not themselves carry credential-shaped text. Also learned
    the hard way: the first draft quoted each matched line, and those quotes
    were five new findings. The file meant to quiet the scan set it on fire.
"""
from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_IGNORE = _ROOT / ".gitleaksignore"
_CONFIG = _ROOT / ".gitleaks.toml"

#: Findings triaged on 2026-08-31 against run 33384506909. Raising this number
#: means a human read the new match in its commit and decided it is not a
#: credential. It is not a knob to turn when CI is inconvenient.
BASELINE_FINDINGS = 22

_FINGERPRINT = re.compile(r"^[0-9a-f]{40}:[^:\s]+:[a-z0-9.\-]+:\d+$")


def _entries() -> list[str]:
    text = _IGNORE.read_text(encoding="utf-8")
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def test_the_baseline_file_exists() -> None:
    assert _IGNORE.exists(), (
        ".gitleaksignore is gone. The full-history scan goes back to failing on "
        f"its {BASELINE_FINDINGS} known matches every run, which makes a real "
        "finding indistinguishable from the noise"
    )


def test_every_entry_is_pinned_to_one_commit() -> None:
    """A fingerprint cannot cover a secret that does not exist yet."""
    bad = [e for e in _entries() if not _FINGERPRINT.match(e)]
    assert not bad, (
        "these .gitleaksignore entries are not `commit:path:rule:line` with a "
        "full 40-character SHA. Anything looser can match commits that have not "
        "been written yet, which turns a reviewed baseline into a blanket "
        "suppression:\n" + "\n".join(f"  {e}" for e in bad)
    )


def test_no_entry_uses_a_glob() -> None:
    """`*.py` or a bare path would silence a file's entire future."""
    offenders = [e for e in _entries() if any(c in e for c in "*?[")]
    assert not offenders, (
        "these entries contain glob characters, so they suppress by pattern "
        "rather than by commit:\n" + "\n".join(f"  {e}" for e in offenders)
    )


def test_the_baseline_count_is_the_declared_one() -> None:
    entries = _entries()
    assert len(entries) == BASELINE_FINDINGS, (
        f".gitleaksignore holds {len(entries)} entries, baseline says "
        f"{BASELINE_FINDINGS}. If a finding was genuinely triaged, update "
        "BASELINE_FINDINGS in this file and say in the PR which commit it was "
        "and why it is not a credential. If entries were removed because the "
        "history was rewritten, note that rewriting is not redaction — the "
        "orphaned commits stay fetchable by SHA and rotation is the remedy"
    )


def test_no_entry_is_duplicated() -> None:
    entries = _entries()
    dupes = {e for e in entries if entries.count(e) > 1}
    assert not dupes, f"duplicate fingerprints inflate the baseline: {sorted(dupes)}"


def test_the_file_has_unix_line_endings() -> None:
    """A trailing CR makes every fingerprint miss, silently."""
    raw = _IGNORE.read_bytes()
    assert b"\r" not in raw, (
        ".gitleaksignore contains carriage returns. gitleaks compares each line "
        "verbatim, so a CRLF entry never matches its finding and the scan stays "
        "red with no visible reason. .gitattributes pins this to eol=lf"
    )


def test_the_comments_carry_no_credential_shaped_text() -> None:
    """The file that quiets the scan must not feed it.

    The first draft of this baseline quoted each matched line verbatim to
    explain it. Those quotes were themselves five new `generic-api-key`
    findings, in a brand-new commit, so they could not be covered by the very
    fingerprints they were annotating. Describe the match; do not reproduce it.
    """
    shape = re.compile(
        r"(key|secret|token|password|passwd|pwd)\s*[:=]\s*[\"'][^\"']{8,}",
        re.IGNORECASE,
    )
    offenders = [
        line.strip()
        for line in _IGNORE.read_text(encoding="utf-8").splitlines()
        if line.lstrip().startswith("#") and shape.search(line)
    ]
    assert not offenders, (
        "these comment lines reproduce a credential-shaped assignment, which "
        "the scanner will flag as new findings in this very commit:\n"
        + "\n".join(f"  {o}" for o in offenders)
        + "\nDescribe what the match was instead of quoting it."
    )


def test_the_config_grows_no_catch_all_allowlist() -> None:
    """The baseline is pointless if .gitleaks.toml quietly silences everything."""
    text = _CONFIG.read_text(encoding="utf-8")
    live = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    catch_alls = ("'''.*'''", '""".*"""', "'''.+'''", "paths = [", "stopwords")
    hits = [line for line in live if any(c in line for c in catch_alls[:3])]
    assert not hits, (
        "a `.*` allowlist regex in .gitleaks.toml disables the scan entirely "
        "while leaving it green:\n" + "\n".join(f"  {h}" for h in hits)
    )


def test_the_fingerprint_pattern_actually_matches_a_real_one() -> None:
    """Guard the guard: a broken regex makes every sweep above pass vacuously."""
    real = "b0bc3847be61b3fd0f859ee894476a32afd931a8:warden/payments/l402.py:generic-api-key:42"
    assert _FINGERPRINT.match(real)
    for bogus in (
        "warden/payments/l402.py",                    # bare path
        "b0bc3847:warden/payments/l402.py:x:42",      # short sha
        "*:*:generic-api-key:1",                      # globs
        "b0bc3847be61b3fd0f859ee894476a32afd931a8:warden/x.py:generic-api-key",  # no line
    ):
        assert not _FINGERPRINT.match(bogus), f"pattern wrongly accepted: {bogus}"
