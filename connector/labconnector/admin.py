"""Server-side helper, run inside the container by the `lab` command.

  check                      validate flows.yaml
  setup <project>            clone the project's repositories and run its setup steps
  run <project> <flow> [k=v] run a flow now (used by the scheduled timers)
  schedules                  print "project<TAB>flow<TAB>when" for every scheduled flow
  projects                   print the project names, one per line
  env-keys <project>         print "file<TAB>NAME<TAB>description" for the secrets a project needs
"""
from __future__ import annotations

import subprocess
import sys

from .runner import FlowError
from .server import make_runner


def _run(argv, cwd) -> None:
    print(f"$ {' '.join(argv)}", flush=True)
    subprocess.run(argv, cwd=cwd, check=True)


def setup(runner, name: str) -> None:
    proj = runner.project(name)
    base = runner.projects_dir
    for repo, path in ([(proj.repo, proj.path)] if proj.repo else []) + list(proj.extra_repos):
        target = base / path
        if (target / ".git").is_dir():
            _run(["git", "pull", "--ff-only", "--autostash"], target)
        else:
            _run(["git", "clone", repo, str(target)], base)
    root = runner.root(name)
    root.mkdir(parents=True, exist_ok=True)
    for step in proj.setup:
        argv = list(step)
        if "/" in argv[0] and not argv[0].startswith("/"):
            argv[0] = str(root / argv[0])
        _run(argv, root)
    print(f"project '{name}' is ready")


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    cmd, args = argv[0], argv[1:]
    try:
        runner = make_runner()
        if cmd == "check":
            n = sum(len(p.flows) for p in runner.projects.values())
            print(f"flows.yaml is valid: {len(runner.projects)} project(s), {n} flow(s)")
        elif cmd == "setup":
            setup(runner, args[0])
        elif cmd == "run":
            params = dict(a.split("=", 1) for a in args[2:])
            job = runner.run_blocking(args[0], args[1], params)
            print(job.output)
            print(f"[{job.status}, exit code {job.exit_code}]")
            return 0 if job.status == "ok" else 1
        elif cmd == "schedules":
            for p in runner.projects.values():
                for f in p.flows.values():
                    if f.schedule:
                        print(f"{p.name}\t{f.name}\t{f.schedule}")
        elif cmd == "projects":
            print("\n".join(runner.projects))
        elif cmd == "env-keys":
            proj = runner.project(args[0])
            for key, desc in proj.env_keys:
                print(f"{proj.env_file}\t{key}\t{desc}")
        else:
            print(__doc__)
            return 2
    except (FlowError, IndexError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
