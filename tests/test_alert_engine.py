from alert_engine import create_alert, load_alerts


def test_create_alert(tmp_path, monkeypatch):
    import alert_engine

    alert_file = tmp_path / "alerts.json"

    monkeypatch.setattr(
        alert_engine,
        "ALERT_FILE",
        str(alert_file),
    )

    process = {
        "pid": 1234,
        "name": "test-process",
        "username": "root",
        "parent": "bash",
        "cpu_percent": 85.0,
        "memory_percent": 2.5,
        "network_connections": 1,
    }

    risk = {
        "score": 80,
        "severity": "CRITICAL",
        "reasons": [
            "Process is running as root",
            "High CPU utilization",
        ],
    }

    alert = create_alert(process, risk)

    assert alert["pid"] == 1234
    assert alert["process_name"] == "test-process"
    assert alert["severity"] == "CRITICAL"
    assert alert["risk_score"] == 80
    assert alert["status"] == "OPEN"
    assert alert["alert_id"].startswith("LC-")


def test_alert_persisted(tmp_path, monkeypatch):
    import alert_engine

    alert_file = tmp_path / "alerts.json"

    monkeypatch.setattr(
        alert_engine,
        "ALERT_FILE",
        str(alert_file),
    )

    process = {
        "pid": 9999,
        "name": "suspicious-process",
        "username": "root",
        "parent": "bash",
        "cpu_percent": 90.0,
        "memory_percent": 5.0,
        "network_connections": 2,
    }

    risk = {
        "score": 90,
        "severity": "CRITICAL",
        "reasons": ["High CPU utilization"],
    }

    create_alert(process, risk)

    alerts = load_alerts()

    assert len(alerts) == 1
    assert alerts[0]["pid"] == 9999

def test_duplicate_alert_is_not_created(tmp_path, monkeypatch):
    import alert_engine

    alert_file = tmp_path / "alerts.json"

    monkeypatch.setattr(
        alert_engine,
        "ALERT_FILE",
        str(alert_file),
    )

    process = {
        "pid": 5555,
        "name": "suspicious-process",
        "username": "root",
        "parent": "bash",
        "cpu_percent": 90.0,
        "memory_percent": 5.0,
        "network_connections": 2,
    }

    risk = {
        "score": 90,
        "severity": "CRITICAL",
        "reasons": ["High CPU utilization"],
    }

    first_alert = create_alert(process, risk)
    second_alert = create_alert(process, risk)

    alerts = load_alerts()

    assert first_alert["alert_id"] == second_alert["alert_id"]
    assert len(alerts) == 1
