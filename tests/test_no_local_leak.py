from __future__ import annotations

import fnmatch
import os
import re
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Iterator


@dataclass(frozen=True)
class IgnoreRules:
    __slots__ = ("directory_names", "path_globs", "binary_suffixes")

    directory_names: frozenset[str]
    path_globs: tuple[str, ...]
    binary_suffixes: frozenset[str]


@dataclass(frozen=True)
class Finding:
    __slots__ = ("path", "label", "line_number", "excerpt")

    path: Path
    label: str
    line_number: int
    excerpt: str


PatternRule = tuple[str, re.Pattern[str]]

BASE_IGNORED_DIRS: Final = frozenset(
    (".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv", "venv")
)
BASE_BINARY_SUFFIXES: Final = frozenset(
    ".br .dat .dll .dylib .exe .gif .gz .ico .jpeg .jpg .mmdb .pdf .png "
    ".pyc .pyd .pyo .so .tar .tgz .xz .zip .zst".split()
)
LOCAL_HOST_PATTERN: Final = (
    r"(?:localhost|[A-Za-z0-9._-]+\.(?:lan|local)|"
    r"(?:Mac|MacBook|iMac|Mac-mini|mbp)(?:[-._][A-Za-z0-9._-]+)?)"
)
MOBILE_DEBUG_PATTERN: Final = (
    r"(?:" + "a" + "db|" + "ANDROID" + "_" + "SERIAL|" + "device" + r"[-_\s]*"
    + "serial" + r"|ro\.serialno|ro\.boot\.serialno|emulator-\d{4})"
)
LEAK_PATTERNS: Final[tuple[PatternRule, ...]] = (
    (
        "home path",
        re.compile(
            r"(?<![A-Za-z0-9._-])(?:/(?:Users|home)/[A-Za-z0-9._-]+"
            r"|[A-Za-z]:\\(?:Users|Documents and Settings)\\[A-Za-z0-9._-]+"
            r"|~[A-Za-z0-9._-]+)(?:[\\/]|$)",
        ),
    ),
    (
        "local temp path",
        re.compile(r"(?<![A-Za-z0-9._-])/(?:private/var/folders|var/folders)(?:/|$)"),
    ),
    (
        "local email identity",
        re.compile(r"\b[A-Za-z0-9._%+-]+@" + LOCAL_HOST_PATTERN + r"\b", re.IGNORECASE),
    ),
    (
        "local shell identity",
        re.compile(
            r"\b[A-Za-z0-9._-]+@"
            r"(?:Mac|MacBook|iMac|Mac-mini|mbp)(?:[-._][A-Za-z0-9._-]+)?(?=[:\s]|$)",
            re.IGNORECASE,
        ),
    ),
    (
        "mobile debug identity",
        re.compile(
            r"\b" + MOBILE_DEBUG_PATTERN + r"\b(?:\s*[:=]\s*[A-Za-z0-9._:-]{4,})?",
            re.IGNORECASE,
        ),
    ),
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_ignore_rules(root: Path) -> IgnoreRules:
    directory_names = set(BASE_IGNORED_DIRS)
    path_globs: list[str] = []
    gitignore_path = root / ".gitignore"
    for raw_line in gitignore_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        if line.endswith("/"):
            directory_names.add(line.rstrip("/").rsplit("/", maxsplit=1)[-1])
        else:
            path_globs.append(line)
    return IgnoreRules(
        directory_names=frozenset(directory_names),
        path_globs=tuple(path_globs),
        binary_suffixes=BASE_BINARY_SUFFIXES,
    )


def _is_ignored_path(path: Path, root: Path, rules: IgnoreRules) -> bool:
    relative = path.relative_to(root)
    if set(relative.parts) & rules.directory_names:
        return True
    if path.suffix.lower() in rules.binary_suffixes:
        return True
    relative_text = relative.as_posix()
    return any(
        fnmatch.fnmatch(relative_text, path_glob) or fnmatch.fnmatch(path.name, path_glob)
        for path_glob in rules.path_globs
    )


def _repository_files(root: Path) -> Iterator[Path]:
    rules = _load_ignore_rules(root)
    for current_root, directory_names, file_names in os.walk(root):
        current_path = Path(current_root)
        directory_names[:] = sorted(
            name for name in directory_names if not _is_ignored_path(current_path / name, root, rules)
        )
        for file_name in sorted(file_names):
            file_path = current_path / file_name
            if not _is_ignored_path(file_path, root, rules):
                yield file_path


def _decode_text(path: Path) -> str | None:
    data = path.read_bytes()
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace")


def _line_excerpt(text: str, index: int) -> str:
    line_start = text.rfind("\n", 0, index) + 1
    line_end = text.find("\n", index)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end].strip()


def _find_text_leaks(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for label, pattern in LEAK_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(
                Finding(
                    path=path,
                    label=label,
                    line_number=text.count("\n", 0, match.start()) + 1,
                    excerpt=_line_excerpt(text, match.start()),
                )
            )
    return findings


def _find_file_leaks(path: Path) -> list[Finding]:
    text = _decode_text(path)
    if text is None:
        return []
    return _find_text_leaks(path, text)


def _format_findings(root: Path, findings: list[Finding]) -> str:
    return "\n".join(
        f"{finding.path.relative_to(root)}:{finding.line_number}: "
        f"{finding.label}: {finding.excerpt}"
        for finding in findings
    )


class NoLocalLeakTests(unittest.TestCase):
    def test_detector_finds_local_machine_markers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sample_path = Path(temp_dir) / "sample.txt"
            home_owner = "local" + "-" + "user"
            host_name = "workstation" + "." + "local"
            content = "\n".join(
                (
                    "/" + "Users" + "/" + home_owner + "/project",
                    "operator" + "@" + host_name,
                    "ANDROID" + "_" + "SERIAL" + "=R" + "58" + "M" + "123456A",
                )
            )
            sample_path.write_text(content, encoding="utf-8")

            labels = {finding.label for finding in _find_file_leaks(sample_path)}

        self.assertGreaterEqual(
            labels,
            {"home path", "local email identity", "mobile debug identity"},
        )

    def test_repository_files_do_not_contain_local_machine_markers(self) -> None:
        root = _repo_root()
        findings: list[Finding] = []

        for path in _repository_files(root):
            findings.extend(_find_file_leaks(path))

        self.assertEqual([], findings, _format_findings(root, findings))


if __name__ == "__main__":
    unittest.main()
