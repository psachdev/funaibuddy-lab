"""Run flows safely.

Rules enforced here:
  * no shell, ever: commands are argument lists
  * parameters must match the pattern written in flows.yaml
  * secrets reach a flow through its environment and are scrubbed from output
  * file reads cannot leave the project folder or touch secret-looking files
  * one flow at a time per project, each with a hard time limit
"""
from __future__ import annotations

import fcntl
import fnmatch
import json
import os
import signal
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .config import PLACEHOLDER_RE, Flow, Project

MAX_OUTPUT_CHARS = 30_000
MAX_READ_BYTES = 200_000
ALWAYS_DENY = (".env", ".env.*", "*.key", "*.pem", "id_rsa*", "id_ed25519*", ".git")
BASE_ENV_KEYS = ("PATH", "LANG", "LC_ALL", "TZ", "HOME", "TMPDIR")


class FlowError(Exception):
    """Something the caller did wrong (bad name, bad parameter, busy)."""


def load_env_file(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if not path.is_file():
        return env
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        env[key.strip().removeprefix("export ").strip()] = value
    return env


def scrub(text: str, secrets: list[str]) -> str:
    for s in sorted({s for s in secrets if len(s) >= 6}, key=len, reverse=True):
        text = text.replace(s, "[hidden]")
    return text


def cap(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    head, tail = limit // 4, limit - limit // 4
    cut = len(text) - head - tail
    return f"{text[:head]}\n\n[... {cut} characters left out ...]\n\n{text[-tail:]}"


def build_steps(flow: Flow, given: dict[str, str] | None) -> list[list[str]]:
    given = {k: str(v) for k, v in (given or {}).items()}
    unknown = set(given) - set(flow.params)
    if unknown:
        raise FlowError(f"unknown parameter(s): {sorted(unknown)}")
    values: dict[str, str] = {}
    for name, param in flow.params.items():
        value = given.get(name, param.default)
        if value is None:
            raise FlowError(f"missing parameter '{name}': {param.description}")
        if value.startswith("-") or "\x00" in value or not param.pattern.fullmatch(value):
            raise FlowError(f"parameter '{name}' is not allowed (must match {param.pattern.pattern})")
        values[name] = value
    return [[PLACEHOLDER_RE.sub(lambda m: values[m.group(1)], arg) for arg in step] for step in flow.steps]


def is_denied(rel_posix: str, patterns: tuple[str, ...]) -> bool:
    """True if the path, any folder above it, or any single name in it matches a pattern."""
    parts = rel_posix.split("/") if rel_posix else []
    candidates = set(parts) | {"/".join(parts[:i]) for i in range(1, len(parts) + 1)}
    return any(fnmatch.fnmatch(c, pat) for c in candidates for pat in patterns)


def safe_path(root: Path, rel: str, deny: tuple[str, ...] = ()) -> Path:
    root = root.resolve()
    target = (root / rel).resolve()
    if target != root and root not in target.parents:
        raise FlowError("that path is outside the project folder")
    rel_posix = target.relative_to(root).as_posix() if target != root else ""
    if is_denied(rel_posix, ALWAYS_DENY + tuple(deny)):
        raise FlowError("that file is blocked by the lab's privacy rules")
    return target


@dataclass
class Job:
    id: str
    project: str
    flow: str
    params: dict[str, str]
    started: float = field(default_factory=time.time)
    finished: float | None = None
    exit_code: int | None = None
    status: str = "running"
    output: str = ""

    def public(self) -> dict:
        return {
            "job_id": self.id,
            "project": self.project,
            "flow": self.flow,
            "status": self.status,
            "exit_code": self.exit_code,
            "seconds": round((self.finished or time.time()) - self.started, 1),
            "output": self.output,
        }


class Runner:
    def __init__(self, projects: dict[str, Project], projects_dir: Path, secrets_dir: Path, logs_dir: Path, extra_secrets: list[str] | None = None, origin: str = "chat"):
        self.projects = projects
        self.projects_dir = Path(projects_dir)
        self.secrets_dir = Path(secrets_dir)
        self.logs_dir = Path(logs_dir)
        self.extra_secrets = list(extra_secrets or [])
        self.origin = origin  # "chat" (through the connector) or "server" (timer or lab command)
        self._jobs: dict[str, Job] = {}

    # ---- lookups -------------------------------------------------------
    def project(self, name: str) -> Project:
        if name not in self.projects:
            raise FlowError(f"no project named '{name}'. Known: {sorted(self.projects)}")
        return self.projects[name]

    def flow(self, project: str, flow: str) -> Flow:
        proj = self.project(project)
        if flow not in proj.flows:
            raise FlowError(f"no flow named '{flow}' in '{project}'. Known: {sorted(proj.flows)}")
        return proj.flows[flow]

    def root(self, project: str) -> Path:
        return self.projects_dir / self.project(project).path

    def _env_for(self, proj: Project, with_secrets: bool) -> tuple[dict[str, str], list[str]]:
        env = {k: os.environ[k] for k in BASE_ENV_KEYS if k in os.environ}
        env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
        env["PYTHONUNBUFFERED"] = "1"
        secrets = list(self.extra_secrets)
        if proj.env_file:
            file_env = load_env_file(self.secrets_dir / proj.env_file)
            secrets += list(file_env.values())
            if with_secrets:
                env.update(file_env)
        return env, secrets

    # ---- running -------------------------------------------------------
    def start(self, project: str, flow_name: str, params: dict[str, str] | None = None) -> Job:
        proj = self.project(project)
        flow = self.flow(project, flow_name)
        steps = build_steps(flow, params)
        root = self.root(project)
        if not root.is_dir():
            raise FlowError(f"project folder is missing; run 'lab project-setup {project}' on the server")
        lock = self._lock(project)
        job = Job(id=uuid.uuid4().hex[:12], project=project, flow=flow_name, params=dict(params or {}))
        self._jobs[job.id] = job
        if len(self._jobs) > 200:
            for old in sorted(self._jobs.values(), key=lambda j: j.started)[:50]:
                if old.status != "running":
                    self._jobs.pop(old.id, None)
        threading.Thread(target=self._work, args=(job, proj, flow, steps, root, lock), daemon=True).start()
        return job

    def _lock(self, project: str):
        """A file lock, so a scheduled run and a chat run can never overlap."""
        (self.logs_dir / "locks").mkdir(parents=True, exist_ok=True)
        fh = (self.logs_dir / "locks" / f"{project}.lock").open("w")
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            fh.close()
            raise FlowError(f"'{project}' is already running a flow; wait for it to finish") from None
        return fh

    def _work(self, job: Job, proj: Project, flow: Flow, steps, root: Path, lock) -> None:
        env, secrets = self._env_for(proj, flow.uses_secrets)
        deadline = job.started + flow.timeout
        chunks: list[str] = []
        code = 0
        try:
            for step in steps:
                argv = list(step)
                if "/" in argv[0] and not os.path.isabs(argv[0]):
                    argv[0] = str(root / argv[0])
                if len(steps) > 1:
                    chunks.append(f"$ {' '.join(step)}\n")
                try:
                    proc = subprocess.Popen(
                        argv, cwd=root, env=env, stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True, errors="replace", start_new_session=True,
                    )
                except OSError as exc:
                    chunks.append(f"could not start: {exc}\n")
                    code = 127
                    break
                try:
                    out, _ = proc.communicate(timeout=max(1, deadline - time.time()))
                    code = proc.returncode
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    out, _ = proc.communicate()
                    chunks.append(out or "")
                    chunks.append(f"\n[stopped: went past the {flow.timeout}-second limit]\n")
                    code = 124
                    job.status = "timed_out"
                    break
                chunks.append(out or "")
                if code != 0:
                    break
        finally:
            job.output = cap(scrub("".join(chunks), secrets))
            job.exit_code = code
            job.finished = time.time()
            if job.status == "running":
                job.status = "ok" if code == 0 else "failed"
            self._record(job)
            lock.close()

    def run_blocking(self, project: str, flow_name: str, params: dict[str, str] | None = None) -> Job:
        job = self.start(project, flow_name, params)
        while job.status == "running":
            time.sleep(0.2)
        return job

    def job(self, job_id: str) -> Job:
        if job_id not in self._jobs:
            raise FlowError("no such job (the connector may have restarted); use last_run instead")
        return self._jobs[job_id]

    # ---- records -------------------------------------------------------
    def _record(self, job: Job) -> None:
        try:
            (self.logs_dir / "last").mkdir(parents=True, exist_ok=True)
            (self.logs_dir / "last" / f"{job.project}.{job.flow}.json").write_text(json.dumps(job.public()))
            with (self.logs_dir / "audit.jsonl").open("a") as fh:
                entry = job.public() | {"params": job.params, "at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "epoch": int(time.time()), "via": self.origin}
                entry.pop("output")
                fh.write(json.dumps(entry) + "\n")
        except OSError:
            pass

    def last_run(self, project: str, flow_name: str) -> dict:
        self.flow(project, flow_name)
        path = self.logs_dir / "last" / f"{project}.{flow_name}.json"
        if not path.is_file():
            return {"status": "never_run", "project": project, "flow": flow_name}
        data = json.loads(path.read_text())
        data["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(path.stat().st_mtime))
        return data

    # ---- files (read only) ---------------------------------------------
    def list_files(self, project: str, rel: str = "") -> list[str]:
        proj = self.project(project)
        target = safe_path(self.root(project), rel or ".", proj.deny_read) if rel else self.root(project).resolve()
        if not target.is_dir():
            raise FlowError("not a folder")
        out = []
        for child in sorted(target.iterdir()):
            if child.name in (".git", ".venv", "__pycache__", ".pytest_cache"):
                continue
            try:
                safe_path(self.root(project), str(child.relative_to(self.root(project).resolve())), proj.deny_read)
            except FlowError:
                continue
            out.append(child.name + ("/" if child.is_dir() else f"  ({child.stat().st_size} bytes)"))
        return out[:500]

    def read_file(self, project: str, rel: str, tail_lines: int = 0) -> str:
        proj = self.project(project)
        target = safe_path(self.root(project), rel, proj.deny_read)
        if not target.is_file():
            raise FlowError("no such file")
        raw = target.read_bytes()
        if b"\x00" in raw[:4096]:
            raise FlowError("that is not a text file")
        text = raw[-MAX_READ_BYTES:].decode("utf-8", errors="replace")
        if tail_lines > 0:
            text = "\n".join(text.splitlines()[-tail_lines:])
        _, secrets = self._env_for(proj, False)
        return cap(scrub(text, secrets))
