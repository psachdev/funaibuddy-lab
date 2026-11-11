import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from labconnector.config import ConfigError, load_config  # noqa: E402
from labconnector.runner import FlowError, Runner, build_steps, cap, safe_path, scrub  # noqa: E402

YAML = """
projects:
  demo:
    path: demo
    env_file: demo.env
    deny_read: [sources, "*.pdf"]
    flows:
      hello:
        command: [python3, -c, "print('hello')"]
      show-env:
        command: [python3, -c, "import os; print(os.environ.get('API_KEY'), os.environ.get('LAB_TOKEN'))"]
      no-secrets:
        command: [python3, -c, "import os; print(os.environ.get('API_KEY'))"]
        uses_secrets: false
      echo:
        command: [python3, -c, "import sys; print(sys.argv[1])", "{word}"]
        params:
          word: {pattern: "[a-z]{1,10}", description: a word}
      slow:
        command: [python3, -c, "import time; time.sleep(30)"]
        timeout: 1
      two-steps:
        steps:
          - [python3, -c, "print('one')"]
          - [python3, -c, "import sys; sys.exit(3)"]
          - [python3, -c, "print('never')"]
"""


@pytest.fixture
def runner(tmp_path):
    (tmp_path / "flows.yaml").write_text(YAML)
    for d in ("projects/demo/sources", "secrets", "logs"):
        (tmp_path / d).mkdir(parents=True)
    (tmp_path / "secrets/demo.env").write_text('API_KEY="sk-supersecret123"\n')
    (tmp_path / "projects/demo/notes.txt").write_text("line1\nline2\nkey is sk-supersecret123\n")
    (tmp_path / "projects/demo/.env").write_text("X=1")
    (tmp_path / "projects/demo/sources/paid.txt").write_text("paid research")
    (tmp_path / "outside.txt").write_text("outside")
    return Runner(load_config(tmp_path / "flows.yaml"), tmp_path / "projects", tmp_path / "secrets", tmp_path / "logs")


def test_runs_a_flow_and_records_it(runner):
    job = runner.run_blocking("demo", "hello")
    assert (job.status, job.exit_code, job.output.strip()) == ("ok", 0, "hello")
    assert runner.last_run("demo", "hello")["status"] == "ok"
    assert (runner.logs_dir / "audit.jsonl").read_text().count("\n") == 1


def test_secret_reaches_the_flow_but_never_the_output(runner):
    out = runner.run_blocking("demo", "show-env").output
    assert "sk-supersecret123" not in out and "[hidden]" in out
    assert "None" in out  # the connector's own token is not passed to flows


def test_flow_can_opt_out_of_secrets(runner):
    assert runner.run_blocking("demo", "no-secrets").output.strip() == "None"


def test_unknown_flow_and_project_are_refused(runner):
    with pytest.raises(FlowError):
        runner.start("demo", "rm-everything")
    with pytest.raises(FlowError):
        runner.start("nope", "hello")


@pytest.mark.parametrize("bad", ["UPPER", "two words", "a;ls", "$(id)", "-x", "", "../etc"])
def test_bad_parameters_are_refused(runner, bad):
    with pytest.raises(FlowError):
        build_steps(runner.flow("demo", "echo"), {"word": bad})


def test_good_parameter_is_passed_as_one_argument(runner):
    assert runner.run_blocking("demo", "echo", {"word": "abc"}).output.strip() == "abc"
    with pytest.raises(FlowError):
        build_steps(runner.flow("demo", "echo"), {"word": "abc", "extra": "x"})
    with pytest.raises(FlowError):
        build_steps(runner.flow("demo", "echo"), {})


def test_time_limit_stops_a_flow(runner):
    start = time.time()
    job = runner.run_blocking("demo", "slow")
    assert job.status == "timed_out" and job.exit_code == 124 and time.time() - start < 10


def test_steps_stop_at_first_failure(runner):
    job = runner.run_blocking("demo", "two-steps")
    assert job.status == "failed" and job.exit_code == 3
    assert "one" in job.output and "never" not in job.output


def test_one_flow_at_a_time_per_project(runner):
    runner.start("demo", "slow")
    with pytest.raises(FlowError):
        runner.start("demo", "hello")
    time.sleep(2.5)
    assert runner.run_blocking("demo", "hello").status == "ok"


@pytest.mark.parametrize("path", ["../outside.txt", "/etc/passwd", ".env", "sources/paid.txt", ".git/config", "a/../../outside.txt"])
def test_file_reads_are_fenced_in(runner, path):
    with pytest.raises(FlowError):
        runner.read_file("demo", path)


def test_symlink_cannot_escape(runner):
    (runner.root("demo") / "link.txt").symlink_to(runner.projects_dir.parent / "outside.txt")
    with pytest.raises(FlowError):
        runner.read_file("demo", "link.txt")


def test_reading_scrubs_secrets_and_supports_tail(runner):
    text = runner.read_file("demo", "notes.txt")
    assert "sk-supersecret123" not in text and "[hidden]" in text
    assert runner.read_file("demo", "notes.txt", tail_lines=1).startswith("key is")


def test_listing_hides_private_things(runner):
    names = " ".join(runner.list_files("demo"))
    assert "notes.txt" in names and ".env" not in names and "sources" not in names


def test_helpers():
    assert scrub("abc secret123 abc", ["secret123", "ab"]) == "abc [hidden] abc"
    assert len(cap("x" * 100_000)) < 31_000
    with pytest.raises(FlowError):
        safe_path(Path("/tmp"), "../etc/passwd")


@pytest.mark.parametrize(
    "body",
    [
        "flows: {a: {command: 'rm -rf /'}}",  # a shell line, not a list
        "flows: {a: {command: [echo, '{x}']}}",  # placeholder without a pattern
        "flows: {a: {command: [echo], params: {x: {pattern: '.*'}}}}",  # unused param
        "flows: {a: {command: [echo], steps: [[echo]]}}",  # both forms
        "path: ../escape\n    flows: {}",
        "env_file: ../../etc/passwd\n    flows: {}",
    ],
)
def test_bad_config_is_refused(tmp_path, body):
    (tmp_path / "f.yaml").write_text(f"projects:\n  demo:\n    {body}\n")
    with pytest.raises(ConfigError):
        load_config(tmp_path / "f.yaml")


def test_example_config_is_valid():
    projects = load_config(Path(__file__).resolve().parents[2] / "flows.example.yaml")
    assert "nightly" in projects["thesis-monitor"].flows
