"""Alert dispatcher tests."""

from secmon.alerts import Alert, dispatch, is_duplicate, mark_dispatched


def test_dedup_and_dispatch(cfg, state, tmp_path, capsys):
    cfg["general"]["log_file"] = str(tmp_path / "log.jsonl")
    a1 = Alert("HIGH", "fail2ban", "ban 1.2.3.4", "f2b:1.2.3.4", {})
    new = dispatch([a1], state, cfg)
    assert len(new) == 1
    captured = capsys.readouterr()
    assert "1.2.3.4" in captured.out
    # second dispatch deduped
    new2 = dispatch([a1], state, cfg)
    assert len(new2) == 0
    captured2 = capsys.readouterr()
    assert captured2.out == ""


def test_silent_when_no_findings(cfg, state, capsys):
    new = dispatch([], state, cfg)
    assert new == []
    assert capsys.readouterr().out == ""


def test_ssh_dedup_until_session_ends(state):
    state["monitor_state"]["active_ssh_sessions"] = {"ssh:9.9.9.9": True}
    a = Alert("CRITICAL", "ssh", "bad", "ssh:9.9.9.9", {})
    mark_dispatched(a, state)
    assert is_duplicate(a, state)
