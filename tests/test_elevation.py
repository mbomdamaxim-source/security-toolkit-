from core import elevation


def test_non_windows_is_not_treated_as_administrator(monkeypatch):
    monkeypatch.setattr(elevation.os, "name", "posix")
    assert elevation.is_administrator() is False


def test_failed_relaunch_does_not_exit(monkeypatch):
    monkeypatch.setattr(elevation, "relaunch_as_administrator", lambda: False)
    exits = []
    assert elevation.request_relaunch_and_exit(exits.append) is False
    assert exits == []


def test_successful_relaunch_exits_current_process(monkeypatch):
    monkeypatch.setattr(elevation, "relaunch_as_administrator", lambda: True)
    exits = []
    assert elevation.request_relaunch_and_exit(exits.append) is True
    assert exits == [0]


def test_relaunch_arguments_drop_script_name_when_frozen(monkeypatch):
    from core import elevation
    monkeypatch.setattr(elevation.sys, "frozen", True, raising=False)
    assert elevation.relaunch_arguments(["C:\\Apps\\Bastion.exe", "--flag"]) == ["--flag"]


def test_relaunch_arguments_keep_script_name_from_source(monkeypatch):
    from core import elevation
    monkeypatch.delattr(elevation.sys, "frozen", raising=False)
    args = elevation.relaunch_arguments(["app.py", "--flag"])
    assert len(args) == 2 and args[1] == "--flag"
