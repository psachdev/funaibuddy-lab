"""Build the security report from three records the lab already keeps:

  audit.jsonl          every flow run (written by the runner)
  refused.jsonl        every request turned away at the door (written by the token gate)
  host-security.json   what only the server itself can see: remote logins, firewall,
                       whether flows.yaml changed (written hourly by `lab security-snapshot`)

The report lists facts and then a short "unusual" list. An empty list means nothing
here needs attention; it does not prove nothing happened.
"""
from __future__ import annotations

import calendar
import json
import time
from collections import Counter
from pathlib import Path

MAX_REFUSED_BYTES = 5_000_000


def log_refusal(logs_dir: Path, ip: str, method: str, path: str, token_len: int, expected_len: int) -> None:
    try:
        target = Path(logs_dir) / "refused.jsonl"
        if target.exists() and target.stat().st_size > MAX_REFUSED_BYTES:
            target.replace(target.with_suffix(".jsonl.old"))
        with target.open("a") as fh:
            fh.write(json.dumps({
                "epoch": int(time.time()), "at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "ip": ip[:60], "method": method[:10], "path": path[:80],
                "with_token": token_len > 0, "token_len": token_len, "expected_len": expected_len,
            }) + "\n")
    except OSError:
        pass


def _offset(stamp: str) -> int:
    """Seconds east of UTC from a stamp ending in +HHMM or -HHMM."""
    tail = stamp[19:]
    if len(tail) == 5 and tail[0] in "+-" and tail[1:].isdigit():
        return (1 if tail[0] == "+" else -1) * (int(tail[1:3]) * 3600 + int(tail[3:5]) * 60)
    return 0


def _lines(path: Path, since: float) -> list[dict]:
    out = []
    if not path.is_file():
        return out
    for line in path.read_text(errors="replace").splitlines()[-20000:]:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if "epoch" not in row and row.get("at"):  # entries written before epochs were recorded
            try:
                row["epoch"] = calendar.timegm(time.strptime(row["at"][:19], "%Y-%m-%dT%H:%M:%S")) - _offset(row["at"])
            except ValueError:
                row["epoch"] = 0
        if row.get("epoch", 0) >= since:
            out.append(row)
    return out


def build_report(logs_dir: Path, hours: int = 24, now: float | None = None) -> dict:
    now = now or time.time()
    hours = max(1, min(int(hours), 24 * 30))
    since = now - hours * 3600
    logs_dir = Path(logs_dir)
    unusual: list[str] = []

    runs = _lines(logs_dir / "audit.jsonl", since)
    failed = [r for r in runs if r.get("status") != "ok"]
    for r in failed:
        unusual.append(f"flow {r.get('project')}/{r.get('flow')} ended as {r.get('status')} at {r.get('at')}")

    refused = _lines(logs_dir / "refused.jsonl", since)
    with_token = [r for r in refused if r.get("with_token")]
    if with_token:
        ips = ", ".join(sorted({r.get("ip", "?") for r in with_token})[:8])
        unusual.append(f"{len(with_token)} request(s) carried a WRONG token (someone may be guessing): from {ips}")

    host_path = logs_dir / "host-security.json"
    host: dict = {}
    if host_path.is_file():
        try:
            host = json.loads(host_path.read_text())
        except ValueError:
            host = {}
    if not host:
        unusual.append("no server snapshot found: run `lab schedules` on the server to start hourly snapshots")
    else:
        age_h = (now - host.get("epoch", 0)) / 3600
        if age_h > 3:
            unusual.append(f"server snapshot is {age_h:.0f} hours old: the hourly snapshot timer may have stopped")
        if host.get("firewall_active") is False:
            unusual.append("the server firewall is OFF")
        if host.get("ssh_passwords_refused") is False:
            unusual.append("remote login is accepting passwords again")
        if host.get("flows_changed"):
            unusual.append("flows.yaml differs from the version last accepted with `lab restart`")
        logins = [l for l in host.get("ssh_logins", []) if l.get("epoch", 0) >= since]
        if logins:
            where = ", ".join(sorted({l.get("ip", "?") for l in logins})[:8])
            unusual.append(f"{len(logins)} remote login(s) to the server from: {where} (expected only if that was you)")

    return {
        "window_hours": hours,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(now)),
        "unusual": unusual,
        "all_clear": not unusual,
        "flow_runs": {
            "total": len(runs),
            "from_chat": sum(1 for r in runs if r.get("via") == "chat"),
            "from_server_timer_or_command": sum(1 for r in runs if r.get("via") == "server"),
            "failed": len(failed),
            "by_flow": dict(Counter(f"{r.get('project')}/{r.get('flow')}" for r in runs)),
            "list": [
                {k: r.get(k) for k in ("at", "project", "flow", "status", "via", "seconds", "params")}
                for r in runs[-60:]
            ],
        },
        "refused_requests": {
            "total": len(refused),
            "without_any_token": len(refused) - len(with_token),
            "with_wrong_token": len(with_token),
            "by_address": dict(Counter(r.get("ip", "?") for r in refused).most_common(10)),
        },
        "server": {
            "snapshot_taken": host.get("at"),
            "firewall_active": host.get("firewall_active"),
            "ssh_passwords_refused": host.get("ssh_passwords_refused"),
            "flows_yaml_changed": host.get("flows_changed"),
            "ssh_logins_in_window": [l for l in host.get("ssh_logins", []) if l.get("epoch", 0) >= since][-20:],
            "ssh_failed_attempts_last_24h": host.get("ssh_failed_attempts"),
            "reboot_needed_for_updates": host.get("reboot_required"),
        },
        "note": "An empty 'unusual' list means nothing here needs attention. Runs made with your real token "
                "from a Claude account look like yours, so also check that 'flow_runs' matches what you remember asking for.",
    }
