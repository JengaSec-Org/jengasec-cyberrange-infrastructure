"""Run the real Bash guards with a curl stub; never contact or mutate a service."""

import json
import os
import pathlib
import shlex
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TARGET = "https://selected-rehearsal.invalid:9443"
PASSED = "rehearsal-guard-passed"


@pytest.fixture
def run_guard(tmp_path):
    private = tmp_path / "etc"
    private.mkdir()
    commands = tmp_path / "bin"
    commands.mkdir()
    log = tmp_path / "curl.jsonl"
    curl = commands / "curl"
    curl.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        "with open(os.environ['GUARD_LOG'], 'a') as stream:\n"
        "    stream.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "sys.stdout.write(os.environ['GUARD_HEADERS'])\n"
        "raise SystemExit(int(os.environ['GUARD_CURL_STATUS']))\n"
    )
    curl.chmod(0o755)

    def run(name, headers, local_mode="0", curl_status=0):
        script = (ROOT / "ai-api/deploy" / name).read_text()
        assert script.count("ETC=/etc/jengasec-ai") == 1
        assert script.count('API="$BASE/api/v1"') == 1
        script = script.replace("ETC=/etc/jengasec-ai", "ETC=" + shlex.quote(str(private)))
        # Stop at the existing API setup boundary, before tokens or rehearsal
        # commands. Moving a guard below this boundary makes these tests fail.
        script = script.replace('API="$BASE/api/v1"', f"printf '%s\\n' '{PASSED}'\nexit 0\n" + 'API="$BASE/api/v1"')
        executable = tmp_path / name
        executable.write_text(script)
        (private / "ai-api.env").write_text("" if local_mode is None else "SCORING_MODE=" + shlex.quote(local_mode) + "\n")
        environment = os.environ.copy()
        environment.pop("SCORING_MODE", None)
        environment.update(PATH=str(commands) + os.pathsep + os.environ["PATH"], GUARD_LOG=str(log),
                           GUARD_HEADERS=headers, GUARD_CURL_STATUS=str(curl_status))
        result = subprocess.run(["bash", str(executable), TARGET], env=environment,
                                capture_output=True, text=True, timeout=5)
        calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        for args in calls:
            assert args[-1] == TARGET + "/healthz"  # The URL override, not a local default.
            assert not any(arg in ("-X", "--request", "--data", "-d") for arg in args)
        return result, calls

    return run


@pytest.mark.parametrize("script", ["smoke.sh", "tour.sh"])
@pytest.mark.parametrize("mode", ["1", "TrUe", "on", "", "misspelled"])
def test_local_scoring_or_unknown_mode_refuses_without_requests(run_guard, script, mode):
    result, calls = run_guard(script, "HTTP/1.1 200 OK\r\n\r\n", local_mode=mode)
    assert result.returncode == 2 and "Refusing shadow rehearsal" in result.stderr
    assert PASSED not in result.stdout and calls == []


@pytest.mark.parametrize("script", ["smoke.sh", "tour.sh"])
@pytest.mark.parametrize("headers", [
    "HTTP/1.1 200 OK\r\nX-JengaSec-Scoring-Mode: website-v2\r\n\r\n",
    "HTTP/2 200\r\nx-jengasec-scoring-mode: unknown\r\n\r\n",
    "HTTP/1.1 200 OK\r\nX-JengaSec-Scoring-Mode:\r\n\r\n",
    "HTTP/1.1 200 OK\r\nX-JengaSec-Scoring-Mode: legacy-shadow\r\nX-JengaSec-Scoring-Mode: website-v2\r\n\r\n",
    "HTTP/1.1 302 Found\r\nLocation: https://different.invalid/healthz\r\n\r\n",
    "HTTP/1.1 200 Connection established\r\n\r\nHTTP/2 200\r\nX-JengaSec-Scoring-Mode: website-v2\r\n\r\n",
])
def test_remote_scoring_redirect_or_ambiguous_mode_refuses_with_stale_local_setting(run_guard, script, headers):
    result, calls = run_guard(script, headers, local_mode="0")
    assert result.returncode == 2 and "Refusing shadow rehearsal" in result.stderr
    assert PASSED not in result.stdout and len(calls) == 1


@pytest.mark.parametrize("script", ["smoke.sh", "tour.sh"])
@pytest.mark.parametrize("headers,local_mode", [
    ("HTTP/1.1 200 OK\r\nX-JengaSec-Scoring-Mode: legacy-shadow\r\n\r\n", "OFF"),
    ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n", None),
    ("HTTP/1.1 200 Connection established\r\n\r\nHTTP/2 200\r\nx-jengasec-scoring-mode: legacy-shadow\r\n\r\n", "false"),
])
def test_current_and_older_legacy_servers_remain_supported(run_guard, script, headers, local_mode):
    result, calls = run_guard(script, headers, local_mode=local_mode)
    assert result.returncode == 0, result.stderr
    assert PASSED in result.stdout and len(calls) == 1


@pytest.mark.parametrize("script", ["smoke.sh", "tour.sh"])
def test_failed_mode_probe_refuses_before_rehearsal(run_guard, script):
    result, calls = run_guard(script, "", curl_status=28)
    assert result.returncode == 2 and "cannot confirm the target mode" in result.stderr
    assert PASSED not in result.stdout and len(calls) == 1
