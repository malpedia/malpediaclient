from __future__ import annotations

import base64
import io
import json
import os
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest
from click.testing import CliRunner, Result

from malpedia import cli
from malpedia.client import Client
from tests.conftest import Recorder

SHA256 = "6ada5c313fa15bd4aa8e43638ded5faacc1737064e66b40ff64a329c12f7a5ef"


@pytest.fixture(autouse=True)
def isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, recorder: Recorder) -> None:
    monkeypatch.delenv(cli.config.TOKEN_ENV, raising=False)
    monkeypatch.setattr(cli.config, "config_path", lambda: tmp_path / "cfg" / "config.json")

    def make_client(*args: Any, **kwargs: Any) -> Client:
        return Client(*args, transport=httpx.MockTransport(recorder), **kwargs)

    monkeypatch.setattr(cli, "Client", make_client)


DUMMY = (cli.click.Context(cli.cli), cli.click.Argument(["family_id"]))


def run(*args: str, stdin: str | None = None) -> Result:
    return CliRunner().invoke(cli.cli, list(args), input=stdin)


def force_state(monkeypatch: pytest.MonkeyPatch, **forced: Any) -> None:
    class Forced(cli.State):
        def __init__(self, **kwargs: Any) -> None:
            super().__init__(**{**kwargs, **forced})

    monkeypatch.setattr(cli, "State", Forced)


def respond(recorder: Recorder, status: int, **kwargs: Any) -> None:
    recorder.response = httpx.Response(status, **kwargs)


def test_list_prints_one_id_per_line(recorder: Recorder) -> None:
    respond(recorder, 200, json=["win.a", "win.b"])
    result = run("family", "list")
    assert result.exit_code == 0
    assert result.stdout == "win.a\nwin.b\n"


def test_json_flag(recorder: Recorder) -> None:
    respond(recorder, 200, json=[{"name": "win.emotet", "alt_names": ["Geodo"]}])
    result = run("--json", "family", "search", "emotet")
    assert json.loads(result.stdout) == [{"name": "win.emotet", "alt_names": ["Geodo"]}]


def test_search_is_tab_separated_when_piped(recorder: Recorder) -> None:
    respond(recorder, 200, json=[{"name": "win.emotet", "alt_names": ["Geodo", "Heodo"]}])
    assert run("family", "search", "emotet").stdout == "win.emotet\tGeodo, Heodo\n"


@pytest.mark.parametrize(
    ("status", "code"),
    [(403, cli.EXIT_AUTH), (401, cli.EXIT_AUTH), (404, cli.EXIT_NOT_FOUND), (500, cli.EXIT_ERROR)],
)
def test_api_errors_exit_codes(recorder: Recorder, status: int, code: int) -> None:
    respond(recorder, status, json={"detail": "nope"})
    result = run("family", "show", "x")
    assert result.exit_code == code
    assert result.stdout == ""
    assert "nope" in result.stderr


def test_invalid_hash_is_a_usage_error(recorder: Recorder) -> None:
    result = run("sample", "info", "xyz")
    assert result.exit_code == 2
    assert recorder.requests == []


def test_tlp_short_names(recorder: Recorder, tmp_path: Path) -> None:
    respond(recorder, 200, text="rule a {}")
    out = tmp_path / "w.yar"
    assert run("yara", "tlp", "white", "-o", str(out)).exit_code == 0
    assert recorder.last.url.path == "/api/get/yara/tlp_white/raw"
    assert out.read_text() == "rule a {}"


def test_yara_rules_to_directory_rejects_traversal(recorder: Recorder, tmp_path: Path) -> None:
    respond(recorder, 200, json={"tlp_white": {"a.yar": "rule a {}", "../../evil.yar": "rule e {}"}})
    result = run("yara", "get", "win.x", "-o", str(tmp_path / "rules"))
    assert result.exit_code == 0
    assert (tmp_path / "rules" / "tlp_white" / "a.yar").read_text() == "rule a {}"
    assert (tmp_path / "rules" / "tlp_white" / "evil.yar").exists()
    assert not (tmp_path / "evil.yar").exists()


def test_yara_rules_printed_as_text(recorder: Recorder) -> None:
    respond(recorder, 200, json={"tlp_white": {"a.yar": "rule a {}\n"}, "tlp_green": {"b.yar": "rule b {}"}})
    assert run("yara", "after", "2024-01-31").stdout == "rule a {}\n\nrule b {}\n"
    assert recorder.last.url.path == "/api/get/yara/after/2024-01-31"


@pytest.fixture
def today(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_today", lambda: "2024-05-06")


def test_yara_sync_first_run_writes_rules_and_state(recorder: Recorder, tmp_path: Path, today: None) -> None:
    respond(recorder, 200, json={"tlp_white": {"a.yar": "rule a {}"}})
    out = tmp_path / "rules"
    result = run("yara", "sync", str(out))
    assert result.exit_code == 0
    assert recorder.last.url.path == "/api/get/yara/after/2000-01-01"
    assert (out / "tlp_white" / "a.yar").read_text() == "rule a {}"
    assert json.loads((out / ".malpedia-sync.json").read_text()) == {"last_sync": "2024-05-05", "authenticated": False}


def test_yara_sync_uses_stored_date(recorder: Recorder, tmp_path: Path, today: None) -> None:
    respond(recorder, 200, json={})
    assert run("yara", "sync", str(tmp_path)).exit_code == 0
    assert run("yara", "sync", str(tmp_path)).exit_code == 0
    assert recorder.last.url.path == "/api/get/yara/after/2024-05-05"


def test_yara_sync_since_overrides_state(recorder: Recorder, tmp_path: Path, today: None) -> None:
    (tmp_path / ".malpedia-sync.json").write_text('{"last_sync": "2024-05-01"}')
    respond(recorder, 200, json={})
    assert run("yara", "sync", str(tmp_path), "--since", "2023-01-02").exit_code == 0
    assert recorder.last.url.path == "/api/get/yara/after/2023-01-02"


@pytest.mark.parametrize("content", ["not json", "[]", '{"last_sync": "yesterday"}', "{}"])
def test_yara_sync_rejects_corrupt_state(recorder: Recorder, tmp_path: Path, content: str) -> None:
    (tmp_path / ".malpedia-sync.json").write_text(content)
    result = run("yara", "sync", str(tmp_path))
    assert result.exit_code == cli.EXIT_ERROR
    assert "--since" in result.stderr
    assert "Traceback" not in result.output
    assert not recorder.requests


def test_yara_sync_keeps_state_when_request_fails(recorder: Recorder, tmp_path: Path, today: None) -> None:
    respond(recorder, 500, json={"detail": "boom"})
    result = run("yara", "sync", str(tmp_path))
    assert result.exit_code == cli.EXIT_ERROR
    assert not (tmp_path / ".malpedia-sync.json").exists()


def test_yara_scan_reports_server_side_rule_errors(recorder: Recorder, tmp_path: Path) -> None:
    rule = tmp_path / "r.yar"
    rule.write_text("bad {")
    respond(recorder, 200, json={"detail": "Line 1: syntax error"})
    result = run("yara", "scan", "win.x", str(rule))
    assert result.exit_code == cli.EXIT_ERROR
    assert "syntax error" in result.stderr

    respond(recorder, 200, json={"detail": "Scan complete."})
    result = run("yara", "scan", "win.x", "-", stdin="rule a { condition: true }")
    assert result.exit_code == 0
    assert recorder.last.content == b"rule a { condition: true }"


def test_sample_download(recorder: Recorder, tmp_path: Path) -> None:
    respond(recorder, 200, json={"packed": base64.b64encode(b"MZ").decode(), "../x": ""})
    result = run("sample", "download", SHA256, "-o", str(tmp_path))
    assert result.exit_code == 0
    assert (tmp_path / f"{SHA256}_packed").read_bytes() == b"MZ"
    assert (tmp_path / f"{SHA256}_x").exists()
    assert "live malware" in result.stderr


def test_binary_output_goes_to_file(recorder: Recorder, tmp_path: Path) -> None:
    respond(recorder, 200, content=b"PK\x03\x04")
    out = tmp_path / "auto.zip"
    assert run("yara", "auto", "--zip", "-o", str(out)).exit_code == 0
    assert out.read_bytes() == b"PK\x03\x04"


def test_login_status_logout(recorder: Recorder, tmp_path: Path) -> None:
    respond(recorder, 200, json={"detail": "Valid token."})
    assert run("auth", "status").exit_code == cli.EXIT_AUTH

    assert run("auth", "login", "--with-token", stdin="tok\n").exit_code == 0
    path = tmp_path / "cfg" / "config.json"
    assert json.loads(path.read_text()) == {"apitoken": "tok"}
    assert path.stat().st_mode & 0o777 == 0o600
    assert recorder.last.headers["Authorization"] == "apitoken tok"

    result = run("auth", "status")
    assert result.exit_code == 0
    assert "config file" in result.stdout

    assert run("auth", "logout").exit_code == 0
    assert not path.exists()


def test_login_rejects_invalid_token(recorder: Recorder, tmp_path: Path) -> None:
    respond(recorder, 401, json={"detail": "Invalid token."})
    result = run("auth", "login", "--with-token", stdin="bad\n")
    assert result.exit_code == cli.EXIT_AUTH
    assert not (tmp_path / "cfg" / "config.json").exists()


def test_env_token_takes_precedence(recorder: Recorder, monkeypatch: pytest.MonkeyPatch) -> None:
    respond(recorder, 200, json={"version": 1, "date": "d"})
    monkeypatch.setenv(cli.config.TOKEN_ENV, "from-env")
    assert run("version").exit_code == 0
    assert recorder.last.headers["Authorization"] == "apitoken from-env"


def test_version_flag() -> None:
    result = run("--version")
    assert result.exit_code == 0
    assert result.stdout.startswith("malpedia, version ")


def test_unwritable_output_is_a_clean_error(recorder: Recorder, tmp_path: Path) -> None:
    respond(recorder, 200, text="rule a {}")
    result = run("yara", "auto", "-o", str(tmp_path / "missing" / "a.yar"))
    assert result.exit_code == cli.EXIT_ERROR
    assert "No such file or directory" in result.stderr


def test_empty_argument_is_a_usage_error(recorder: Recorder) -> None:
    result = run("family", "show", "")
    assert result.exit_code == cli.EXIT_USAGE
    assert recorder.requests == []


def test_force_color_does_not_affect_piped_output(recorder: Recorder, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORCE_COLOR", "1")
    respond(recorder, 200, content=b"PK\x03\x04")
    assert run("yara", "auto", "--zip").stdout_bytes == b"PK\x03\x04"
    respond(recorder, 200, json={"a": 1})
    assert run("family", "show", "x").stdout == '{"a": 1}\n'


def test_interrupt_exits_130(recorder: Recorder) -> None:
    def interrupt(request: httpx.Request) -> httpx.Response:
        raise KeyboardInterrupt

    recorder.response = interrupt
    assert run("version").exit_code == cli.EXIT_INTERRUPTED


def test_markup_in_server_text_is_printed_literally(recorder: Recorder) -> None:
    respond(recorder, 404, json={"detail": "no [bold]family[/] at [/tmp/x]"})
    result = run("family", "show", "x")
    assert result.exit_code == cli.EXIT_NOT_FOUND
    assert "no [bold]family[/] at [/tmp/x]" in result.stderr


def test_non_ascii_output_is_utf8_when_piped(recorder: Recorder) -> None:
    respond(recorder, 200, json=[{"name": "x", "common_name": "Фанси", "synonyms": []}])
    result = CliRunner(charset="cp1252").invoke(cli.cli, ["--json", "actor", "search", "x"])
    assert result.exit_code == 0
    assert json.loads(result.stdout_bytes.decode()) == [{"name": "x", "common_name": "Фанси", "synonyms": []}]


def test_completion_script_uses_the_env_var() -> None:
    result = run("completion", "bash")
    assert result.exit_code == 0
    assert "_MALPEDIA_COMPLETE" in result.stdout


def test_family_completion_filters_by_prefix_and_writes_cache(
    recorder: Recorder, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    respond(recorder, 200, json=["win.emotet", "win.emdivi", "elf.mirai"])
    items = cli.complete_family_id(*DUMMY, "win.em")
    assert [item.value for item in items] == ["win.emotet", "win.emdivi"]
    cached = json.loads((tmp_path / "cache" / "malpedia" / "families.json").read_text())
    assert cached == ["win.emotet", "win.emdivi", "elf.mirai"]


def test_actor_completion_filters_by_prefix(
    recorder: Recorder, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    respond(recorder, 200, json=["apt28", "apt29", "lazarus_group"])
    items = cli.complete_actor_id(*DUMMY, "apt")
    assert [item.value for item in items] == ["apt28", "apt29"]


def test_fresh_cache_needs_no_request(recorder: Recorder, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    (tmp_path / "malpedia").mkdir()
    (tmp_path / "malpedia" / "families.json").write_text('["win.a", "elf.b"]')
    items = cli.complete_family_id(*DUMMY, "win")
    assert [item.value for item in items] == ["win.a"]
    assert recorder.requests == []


def test_completion_api_error_without_cache_returns_nothing(
    recorder: Recorder, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    respond(recorder, 500, json={"detail": "boom"})
    assert cli.complete_family_id(*DUMMY, "") == []


def test_global_options_after_the_command(recorder: Recorder) -> None:
    respond(recorder, 200, json=[{"name": "win.emotet", "alt_names": []}])
    result = run("family", "search", "emotet", "--json", "--timeout", "5", "-q", "--no-color")
    assert result.exit_code == 0
    assert json.loads(result.stdout) == [{"name": "win.emotet", "alt_names": []}]
    assert run("family", "show", "x", "--timeout", "0").exit_code == cli.EXIT_USAGE


def test_yara_sync_refetches_everything_after_login(
    recorder: Recorder, tmp_path: Path, today: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    respond(recorder, 200, json={})
    (tmp_path / ".malpedia-sync.json").write_text('{"last_sync": "2024-05-01", "authenticated": false}')
    monkeypatch.setenv(cli.config.TOKEN_ENV, "tok")
    assert run("yara", "sync", str(tmp_path)).exit_code == 0
    assert recorder.last.url.path == "/api/get/yara/after/2000-01-01"
    assert json.loads((tmp_path / ".malpedia-sync.json").read_text())["authenticated"] is True


def test_global_options_between_group_and_command(recorder: Recorder) -> None:
    respond(recorder, 200, json=["win.a"])
    result = run("family", "--json", "list")
    assert result.exit_code == 0
    assert json.loads(result.stdout) == ["win.a"]


def test_failed_completion_refresh_backs_off(
    recorder: Recorder, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    cache = tmp_path / "malpedia" / "families.json"
    cache.parent.mkdir()
    cache.write_text('["win.old"]')
    os.utime(cache, (0, 0))
    respond(recorder, 500)
    assert [item.value for item in cli.complete_family_id(*DUMMY, "win")] == ["win.old"]
    assert len(recorder.requests) == 1
    assert [item.value for item in cli.complete_family_id(*DUMMY, "win")] == ["win.old"]
    assert len(recorder.requests) == 1


def test_yara_sync_moves_rules_between_tlp_levels(recorder: Recorder, tmp_path: Path, today: None) -> None:
    (tmp_path / "tlp_amber").mkdir()
    (tmp_path / "tlp_amber" / "a.yar").write_text("old")
    respond(recorder, 200, json={"tlp_white": {"a.yar": "rule a {}"}})
    assert run("yara", "sync", str(tmp_path)).exit_code == 0
    assert not (tmp_path / "tlp_amber" / "a.yar").exists()
    assert (tmp_path / "tlp_white" / "a.yar").read_text() == "rule a {}"


def test_yara_sync_since_keeps_pending_full_resync(
    recorder: Recorder, tmp_path: Path, today: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    respond(recorder, 200, json={})
    monkeypatch.setenv(cli.config.TOKEN_ENV, "tok")
    assert run("yara", "sync", str(tmp_path), "--since", "2024-05-01").exit_code == 0
    assert json.loads((tmp_path / ".malpedia-sync.json").read_text())["authenticated"] is False
    assert run("yara", "sync", str(tmp_path)).exit_code == 0
    assert recorder.last.url.path == "/api/get/yara/after/2000-01-01"


def test_yara_sync_json(recorder: Recorder, tmp_path: Path, today: None) -> None:
    respond(recorder, 200, json={"tlp_white": {"a.yar": "rule a {}"}})
    result = run("yara", "sync", str(tmp_path), "--json")
    assert json.loads(result.stdout) == [str(tmp_path / "tlp_white" / "a.yar")]


def test_completion_works_with_unwritable_cache(
    recorder: Recorder, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("")
    monkeypatch.setenv("XDG_CACHE_HOME", str(blocker))
    respond(recorder, 200, json=["win.a", None])
    assert [item.value for item in cli.complete_family_id(*DUMMY, "win")] == ["win.a"]


def test_offline_completion_without_cache_backs_off(
    recorder: Recorder, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    respond(recorder, 500)
    assert cli.complete_family_id(*DUMMY, "win") == []
    assert cli.complete_family_id(*DUMMY, "win") == []
    assert len(recorder.requests) == 1


def test_relative_xdg_cache_home_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", "relative")
    assert cli.config.cache_dir().is_absolute()


def versioned(recorder: Recorder, version: int, data: Any) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("get/version"):
            return httpx.Response(200, json={"version": version, "date": "2026-01-01"})
        return httpx.Response(200, json=data)

    recorder.response = handle


def data_requests(recorder: Recorder) -> list[str]:
    return [r.url.path for r in recorder.requests if not r.url.path.endswith("get/version")]


def test_cache_hit_only_checks_the_version(recorder: Recorder, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    versioned(recorder, 5, ["win.a", "win.b"])
    assert run("family", "list").stdout == "win.a\nwin.b\n"
    cached = json.loads((tmp_path / "malpedia" / "data" / "list-families.json").read_text())
    assert cached == {"version": 5, "account": None, "data": ["win.a", "win.b"]}
    recorder.requests.clear()
    assert run("family", "list").stdout == "win.a\nwin.b\n"
    assert [r.url.path for r in recorder.requests] == ["/api/get/version"]


def test_version_change_refetches(recorder: Recorder, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    versioned(recorder, 5, ["win.a"])
    run("actor", "list")
    versioned(recorder, 6, ["apt1"])
    recorder.requests.clear()
    assert run("actor", "list").stdout == "apt1\n"
    assert data_requests(recorder) == ["/api/list/actors"]


def test_auth_change_refetches(recorder: Recorder, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    versioned(recorder, 5, {"a": 1})
    run("export", "misp")
    recorder.requests.clear()
    monkeypatch.setenv(cli.config.TOKEN_ENV, "secret")
    run("export", "misp")
    assert data_requests(recorder) == ["/api/get/misp"]
    recorder.requests.clear()
    run("export", "misp")
    assert data_requests(recorder) == []
    monkeypatch.setenv(cli.config.TOKEN_ENV, "other")
    run("export", "misp")
    assert data_requests(recorder) == ["/api/get/misp"]
    assert "secret" not in (tmp_path / "malpedia" / "data" / "get-misp.json").read_text()


def test_no_cache_refetches_and_writes(recorder: Recorder, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    versioned(recorder, 5, ["win.a"])
    run("family", "list")
    versioned(recorder, 5, ["win.b"])
    recorder.requests.clear()
    assert run("--no-cache", "family", "list").stdout == "win.b\n"
    assert data_requests(recorder) == ["/api/list/families"]
    assert run("family", "list", "--no-cache").stdout == "win.b\n"
    assert run("family", "list").stdout == "win.b\n"
    assert len(data_requests(recorder)) == 2


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        "[]",
        '{"version": 5}',
        '{"version": 5, "account": null}',
        '{"version": 5, "account": null, "data": 1}',
    ],
)
def test_corrupt_cache_falls_back_to_the_network(
    recorder: Recorder, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, content: str
) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    path = tmp_path / "malpedia" / "data" / "list-families.json"
    path.parent.mkdir(parents=True)
    path.write_text(content)
    versioned(recorder, 5, ["win.a"])
    assert run("family", "list").stdout == "win.a\n"
    assert json.loads(path.read_text())["data"] == ["win.a"]


def test_version_is_checked_once_per_invocation(
    recorder: Recorder, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    versioned(recorder, 5, ["win.a"])
    state = cli.State()
    state.cached("a", lambda: [1], list)
    state.cached("b", lambda: [2], list)
    state.close()
    assert [r.url.path for r in recorder.requests] == ["/api/get/version"]


def force_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    force_state(monkeypatch, tty=True)


FAMILY = {
    "common_name": "Emo[bold]tet[/]",
    "alt_names": ["Geodo"],
    "attribution": ["TA542"],
    "description": "x " * 150,
    "urls": ["a", "b"],
    "updated": "2026-10-28",
}


def test_family_show_prints_a_summary_on_a_terminal(recorder: Recorder, monkeypatch: pytest.MonkeyPatch) -> None:
    force_tty(monkeypatch)
    respond(recorder, 200, json=FAMILY)
    result = CliRunner(env={"COLUMNS": "120"}).invoke(cli.cli, ["family", "show", "win.emotet"])
    assert result.exit_code == 0
    assert "Emo[bold]tet[/]" in result.stdout
    assert result.stdout.count("x") == 100
    assert "https://malpedia.caad.fkie.fraunhofer.de/details/win.emotet" in result.stdout
    assert "--json" in result.stdout
    assert not result.stdout.lstrip().startswith("{")


def test_actor_show_prints_a_summary_on_a_terminal(recorder: Recorder, monkeypatch: pytest.MonkeyPatch) -> None:
    force_tty(monkeypatch)
    actor = {
        "value": "APT28",
        "description": "d",
        "meta": {"country": "RU", "synonyms": [f"s{i}" for i in range(12)], "refs": ["r"]},
        "families": {"a": {}, "b": {}},
    }
    respond(recorder, 200, json=actor)
    result = CliRunner(env={"COLUMNS": "120"}).invoke(cli.cli, ["actor", "show", "apt28"])
    assert result.exit_code == 0
    assert "s9" in result.stdout
    assert "s10" not in result.stdout
    assert "+2 more" in result.stdout
    assert "https://malpedia.caad.fkie.fraunhofer.de/actor/apt28" in result.stdout


def test_show_json_is_unchanged_when_piped_or_requested(recorder: Recorder, monkeypatch: pytest.MonkeyPatch) -> None:
    respond(recorder, 200, json=FAMILY)
    assert json.loads(run("family", "show", "win.emotet").stdout) == FAMILY
    force_tty(monkeypatch)
    assert json.loads(run("--json", "family", "show", "win.emotet").stdout) == FAMILY


@pytest.mark.parametrize(
    ("args", "path"),
    [
        (("yara", "get", "win.a", "--zip"), "/api/get/yara/win.a/zip"),
        (("yara", "tlp", "green", "--zip"), "/api/get/yara/tlp_green/zip"),
        (("yara", "tlp", "green"), "/api/get/yara/tlp_green/raw"),
        (("yara", "auto"), "/api/get/yara/auto/raw"),
        (("export", "bib"), "/api/get/bib"),
        (("apiscout", "list", "--csv"), "/api/list/apiscout/csv"),
    ],
    ids=["yara-get-zip", "yara-tlp-zip", "yara-tlp", "yara-auto", "export-bib", "apiscout-csv"],
)
def test_file_outputs_are_streamed(recorder: Recorder, tmp_path: Path, args: tuple[str, ...], path: str) -> None:
    respond(recorder, 200, content=b"x" * 3000)
    out = tmp_path / "out"
    result = run(*args, "-o", str(out))
    assert result.exit_code == 0, result.output
    assert recorder.last.url.path == path
    assert out.read_bytes() == b"x" * 3000
    assert f"Wrote {out} (2.9 KB)\n" in result.stderr
    assert list(tmp_path.iterdir()) == [out]


def test_failed_download_keeps_existing_file(recorder: Recorder, tmp_path: Path) -> None:
    out = tmp_path / "rules.yar"
    out.write_text("old")
    respond(recorder, 404, json={"detail": "nope"})
    assert run("yara", "tlp", "white", "-o", str(out)).exit_code == cli.EXIT_NOT_FOUND
    assert out.read_text() == "old"
    assert list(tmp_path.iterdir()) == [out]


def test_download_shows_progress_on_a_terminal(
    recorder: Recorder, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    err = io.StringIO()
    console = cli.Console(file=err, force_terminal=True, width=80)
    force_state(monkeypatch, err=console)
    respond(recorder, 200, content=b"PK" * 100, headers={"Content-Length": "200"})
    out = tmp_path / "a.zip"
    assert run("yara", "auto", "--zip", "-o", str(out)).exit_code == 0
    assert out.read_bytes() == b"PK" * 100
    assert "a.zip" in err.getvalue()
    assert "200 bytes" in err.getvalue()


def test_binary_download_refuses_a_terminal(recorder: Recorder, monkeypatch: pytest.MonkeyPatch) -> None:
    force_state(monkeypatch, tty=True)
    result = run("yara", "get", "win.a", "--zip")
    assert result.exit_code == cli.EXIT_ERROR
    assert "refusing" in result.stderr
    assert recorder.requests == []


def test_unreachable_version_check_fails_once(recorder: Recorder) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    recorder.response = handle
    result = run("family", "list")
    assert result.exit_code == cli.EXIT_ERROR
    assert [r.url.path for r in recorder.requests] == ["/api/get/version"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file semantics")
def test_download_keeps_the_mode_of_an_existing_file(recorder: Recorder, tmp_path: Path) -> None:
    out = tmp_path / "rules.yar"
    out.write_text("old")
    out.chmod(0o600)
    respond(recorder, 200, content=b"rule a {}")
    assert run("yara", "auto", "-o", str(out)).exit_code == 0
    assert out.read_bytes() == b"rule a {}"
    assert out.stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file semantics")
def test_download_through_a_symlink_updates_the_target(recorder: Recorder, tmp_path: Path) -> None:
    target = tmp_path / "target.yar"
    target.write_text("old")
    link = tmp_path / "link.yar"
    link.symlink_to(target)
    respond(recorder, 200, content=b"rule a {}")
    assert run("yara", "auto", "-o", str(link)).exit_code == 0
    assert link.is_symlink()
    assert target.read_bytes() == b"rule a {}"


def test_download_to_a_missing_directory_names_the_output(recorder: Recorder, tmp_path: Path) -> None:
    out = tmp_path / "missing" / "rules.zip"
    result = run("yara", "get", "win.a", "--zip", "-o", str(out))
    assert result.exit_code == cli.EXIT_ERROR
    assert str(out) in result.stderr
    assert ".part" not in result.stderr


def test_failed_version_check_falls_back_to_the_data(recorder: Recorder) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("get/version"):
            return httpx.Response(404, json={"detail": "Not Found"})
        return httpx.Response(200, json=["win.a"])

    recorder.response = handle
    assert run("family", "list").stdout == "win.a\n"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file semantics")
def test_failed_download_through_a_symlink_keeps_the_target(recorder: Recorder, tmp_path: Path) -> None:
    target = tmp_path / "target.yar"
    target.write_text("old")
    link = tmp_path / "link.yar"
    link.symlink_to(target)
    respond(recorder, 404, json={"detail": "nope"})
    assert run("yara", "auto", "-o", str(link)).exit_code == cli.EXIT_NOT_FOUND
    assert target.read_text() == "old"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["link.yar", "target.yar"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file semantics")
def test_new_download_gets_default_permissions(recorder: Recorder, tmp_path: Path) -> None:
    old = os.umask(0o022)
    try:
        respond(recorder, 200, content=b"rule a {}")
        assert run("yara", "auto", "-o", str(tmp_path / "a.yar")).exit_code == 0
    finally:
        os.umask(old)
    assert (tmp_path / "a.yar").stat().st_mode & 0o777 == 0o644
