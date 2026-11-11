"""Load and validate flows.yaml.

The file is the whole security policy: a flow that is not written here
cannot be run, and a parameter that does not match its pattern is refused.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,40}$")
PLACEHOLDER_RE = re.compile(r"\{([a-z_][a-z0-9_]*)\}")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Param:
    name: str
    pattern: re.Pattern
    description: str = ""
    default: str | None = None


@dataclass(frozen=True)
class Flow:
    name: str
    description: str
    steps: tuple[tuple[str, ...], ...]
    params: dict[str, Param] = field(default_factory=dict)
    timeout: int = 300
    schedule: str | None = None
    uses_secrets: bool = True


@dataclass(frozen=True)
class Project:
    name: str
    path: str
    description: str = ""
    repo: str | None = None
    extra_repos: tuple[tuple[str, str], ...] = ()
    env_file: str | None = None
    env_keys: tuple[tuple[str, str], ...] = ()
    setup: tuple[tuple[str, ...], ...] = ()
    deny_read: tuple[str, ...] = ()
    flows: dict[str, Flow] = field(default_factory=dict)


def _command(raw, where: str) -> tuple[str, ...]:
    if not isinstance(raw, list) or not raw or not all(isinstance(a, str) for a in raw):
        raise ConfigError(f"{where}: a command must be a non-empty list of strings")
    return tuple(raw)


def _rel_dir(value: str, where: str) -> str:
    p = Path(value)
    if p.is_absolute() or ".." in p.parts or not value.strip():
        raise ConfigError(f"{where}: must be a plain relative folder name")
    return value


def _flow(pname: str, fname: str, raw: dict) -> Flow:
    where = f"{pname}.{fname}"
    if not NAME_RE.match(fname):
        raise ConfigError(f"{where}: bad flow name")
    if ("command" in raw) == ("steps" in raw):
        raise ConfigError(f"{where}: give exactly one of 'command' or 'steps'")
    steps = (
        (_command(raw["command"], where),)
        if "command" in raw
        else tuple(_command(s, where) for s in raw["steps"])
    )
    params: dict[str, Param] = {}
    for name, spec in (raw.get("params") or {}).items():
        if not isinstance(spec, dict) or "pattern" not in spec:
            raise ConfigError(f"{where}: param '{name}' needs a 'pattern'")
        try:
            pattern = re.compile(spec["pattern"])
        except re.error as exc:
            raise ConfigError(f"{where}: param '{name}' pattern: {exc}") from exc
        default = spec.get("default")
        params[name] = Param(
            name=name,
            pattern=pattern,
            description=str(spec.get("description", "")),
            default=None if default is None else str(default),
        )
    used = {m for step in steps for arg in step for m in PLACEHOLDER_RE.findall(arg)}
    if used - set(params):
        raise ConfigError(f"{where}: placeholders without a param: {sorted(used - set(params))}")
    if set(params) - used:
        raise ConfigError(f"{where}: params never used: {sorted(set(params) - used)}")
    timeout = int(raw.get("timeout", 300))
    if not 1 <= timeout <= 6 * 3600:
        raise ConfigError(f"{where}: timeout must be between 1 second and 6 hours")
    return Flow(
        name=fname,
        description=str(raw.get("description", "")),
        steps=steps,
        params=params,
        timeout=timeout,
        schedule=raw.get("schedule"),
        uses_secrets=bool(raw.get("uses_secrets", True)),
    )


def load_config(path: str | Path) -> dict[str, Project]:
    data = yaml.safe_load(Path(path).read_text()) or {}
    projects: dict[str, Project] = {}
    for pname, raw in (data.get("projects") or {}).items():
        if not NAME_RE.match(pname):
            raise ConfigError(f"{pname}: bad project name")
        flows = {f: _flow(pname, f, spec) for f, spec in (raw.get("flows") or {}).items()}
        for f in flows.values():
            if f.schedule and f.params and any(p.default is None for p in f.params.values()):
                raise ConfigError(f"{pname}.{f.name}: a scheduled flow cannot need parameters")
        env_file = raw.get("env_file")
        if env_file and (Path(env_file).name != env_file):
            raise ConfigError(f"{pname}: env_file must be a bare file name")
        projects[pname] = Project(
            name=pname,
            path=_rel_dir(raw.get("path", pname), f"{pname}.path"),
            description=str(raw.get("description", "")),
            repo=raw.get("repo"),
            extra_repos=tuple(
                (r["repo"], _rel_dir(r["path"], f"{pname}.extra_repos"))
                for r in (raw.get("extra_repos") or [])
            ),
            env_file=env_file,
            env_keys=tuple(
                (k["name"], str(k.get("description", ""))) for k in (raw.get("env_keys") or [])
            ),
            setup=tuple(_command(s, f"{pname}.setup") for s in (raw.get("setup") or [])),
            deny_read=tuple(raw.get("deny_read") or ()),
            flows=flows,
        )
    return projects
