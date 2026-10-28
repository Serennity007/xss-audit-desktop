"""Project scan settings; paths and globs are relative to the project root."""
from __future__ import annotations

import tomllib
from dataclasses import dataclass
from fnmatch import fnmatchcase
from functools import lru_cache
from pathlib import Path

HARD_LIMITS = {"max_file_bytes": 16 * 1024 * 1024, "max_total_bytes": 512 * 1024 * 1024,
               "max_files": 50000, "max_matches": 50000}


def _patterns(value, name):
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"scan.{name} must be an array of relative POSIX globs.")
    result = []
    for pattern in value:
        if not isinstance(pattern, str):
            raise ValueError(f"scan.{name} must contain only strings.")
        while pattern.startswith("./"):
            pattern = pattern[2:]
        pattern = pattern.rstrip("/")
        if (not pattern or len(pattern) > 512 or len(pattern.split("/")) > 64 or pattern.startswith("/") or "\\" in pattern or ":" in pattern
                or any(ord(char) < 32 for char in pattern)
                or any(part in {"", ".", ".."} for part in pattern.split("/"))):
            raise ValueError(f"scan.{name} must use relative POSIX globs without '..'.")
        result.append(pattern)
    return tuple(result)


@lru_cache(maxsize=8192)
def _match(parts, pattern):
    """Match whole paths: '*' stays in one component; '**' spans zero or more."""
    if not pattern:
        return not parts
    if pattern[0] == "**":
        return _match(parts, pattern[1:]) or bool(parts) and _match(parts[1:], pattern)
    return bool(parts) and fnmatchcase(parts[0], pattern[0]) and _match(parts[1:], pattern[1:])


@dataclass(frozen=True)
class ScanConfig:
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    max_file_bytes: int = 1024 * 1024
    max_total_bytes: int = 100 * 1024 * 1024
    max_files: int = 10000
    max_matches: int = 10000
    strict: bool = True

    def __post_init__(self):
        for name in ("include", "exclude"):
            object.__setattr__(self, name, _patterns(getattr(self, name), name))
        for name in ("max_file_bytes", "max_total_bytes", "max_files", "max_matches"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"scan.{name} must be a positive integer.")
            if value > HARD_LIMITS[name]:
                raise ValueError(f"scan.{name} exceeds the hard limit of {HARD_LIMITS[name]}.")
        if type(self.strict) is not bool:
            raise ValueError("scan.strict must be a boolean.")

    def excludes_directory(self, rel: str) -> bool:
        """Whether a directory can be pruned, including exclusions of its parents."""
        parts = tuple(rel.rstrip("/").split("/"))
        return any(_match(parts[:end], tuple(pattern.split("/")))
                   for pattern in self.exclude for end in range(1, len(parts) + 1))

    def allows_file(self, rel: str) -> bool:
        """Apply configured globs; supported extensions remain the scanner's job.

        Patterns match from the root. An excluded directory excludes its entire
        subtree; include patterns never override exclusions or prune directories.
        """
        parts = tuple(rel.split("/"))
        included = not self.include or any(_match(parts, tuple(pattern.split("/"))) for pattern in self.include)
        return included and not self.excludes_directory(rel)

    def to_dict(self) -> dict:
        return {"include": list(self.include), "exclude": list(self.exclude),
                "max_file_bytes": self.max_file_bytes, "max_total_bytes": self.max_total_bytes,
                "max_files": self.max_files, "max_matches": self.max_matches, "strict": self.strict}


def load_config(root: str | Path, config_path: str | Path | None = None) -> ScanConfig:
    """Read [scan] from .xss-audit.toml or an explicitly selected TOML file.

    A missing default file uses defaults. A missing explicit file, malformed
    configuration, unknown setting, or invalid value raises ValueError.
    """
    base = Path(root).expanduser().resolve()
    path = Path(config_path).expanduser() if config_path is not None else Path(".xss-audit.toml")
    if not path.is_absolute():
        path = base / path
    try:
        with path.open("rb") as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise ValueError("Scan configuration exceeds 64 KiB.")
        text = raw.decode("utf-8-sig")
    except FileNotFoundError as error:
        if config_path is None:
            return ScanConfig()
        raise ValueError(f"Scan configuration does not exist: {path}") from error
    except (OSError, UnicodeError) as error:
        raise ValueError(f"Cannot read scan configuration: {path} ({type(error).__name__})") from error
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise ValueError(f"Invalid scan configuration: {path}: {error}") from error
    if set(data) - {"scan"}:
        raise ValueError("Only the [scan] section is supported in scan configuration.")
    settings = data.get("scan", {})
    if not isinstance(settings, dict):
        raise ValueError("Scan configuration requires a [scan] table.")
    unknown = set(settings) - set(ScanConfig.__dataclass_fields__)
    if unknown:
        raise ValueError("Unknown scan settings: " + ", ".join(sorted(unknown)))
    return ScanConfig(**settings)
