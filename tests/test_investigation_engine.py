from investigation_engine import (
    build_investigation,
)


def test_build_investigation():

    alert = {
        "alert_id": "LC-TEST-001",
        "pid": 1234,
        "process_name": "suspicious-process",
        "username": "root",
        "parent": "bash",
        "exe": "/tmp/test",
        "cmdline": [
            "/tmp/test",
            "--run",
        ],
        "cpu_percent": 95.0,
        "memory_percent": 2.0,
        "network_connections": 2,
        "risk_score": 90,
        "severity": "CRITICAL",
        "detections": [
            {
                "rule_id": "LC-R002",
                "name": "Suspicious Temporary Execution",
                "mitre_id": "T1204",
                "mitre_name": "User Execution",
                "severity": "HIGH",
            }
        ],
    }

    investigation = build_investigation(
        alert
    )

    assert investigation[
        "alert_id"
    ] == "LC-TEST-001"

    assert investigation[
        "status"
    ] == "NEW"

    assert investigation[
        "detection_count"
    ] == 1

    assert investigation[
        "mitre_techniques"
    ][0]["id"] == "T1204"

    assert investigation[
        "evidence"
    ]["executable"] == "/tmp/test"


def test_duplicate_mitre_techniques_removed():

    alert = {
        "alert_id": "LC-TEST-002",
        "risk_score": 80,
        "severity": "HIGH",
        "detections": [
            {
                "rule_id": "LC-R001",
                "mitre_id": "T1078",
                "mitre_name": "Valid Accounts",
            },
            {
                "rule_id": "LC-R001",
                "mitre_id": "T1078",
                "mitre_name": "Valid Accounts",
            },
        ],
    }

    investigation = build_investigation(
        alert
    )

    assert len(
        investigation["mitre_techniques"]
    ) == 1

