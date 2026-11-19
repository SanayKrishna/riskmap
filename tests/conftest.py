import pytest


@pytest.fixture(autouse=True)
def _isolated_incidents(tmp_path, monkeypatch):
    """Correlation runs inside log_event, so every test needs its own incidents file
    or it would write security_incidents.jsonl into the project folder."""
    monkeypatch.setenv("SECURITY_INCIDENTS_PATH", str(tmp_path / "incidents.jsonl"))
