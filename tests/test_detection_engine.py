from detection_engine import (
    evaluate_detections,
    get_rule,
)


def base_process():
    return {
        "pid": 1234,
        "name": "test-process",
        "username": "viswa",
        "exe": "/usr/bin/test",
        "parent": "systemd",
        "cpu_percent": 10.0,
        "memory_percent": 1.0,
        "network_connections": 0,
    }


def test_normal_process_has_no_detections():

    process = base_process()

    detections = evaluate_detections(
        process
    )

    assert detections == []


def test_root_detection():

    process = base_process()
    process["username"] = "root"

    detections = evaluate_detections(
        process
    )

    assert any(
        d["rule_id"] == "LC-R001"
        for d in detections
    )


def test_temporary_path_detection():

    process = base_process()
    process["exe"] = "/tmp/test"

    detections = evaluate_detections(
        process
    )

    assert any(
        d["rule_id"] == "LC-R002"
        for d in detections
    )


def test_shell_parent_detection():

    process = base_process()
    process["parent"] = "bash"

    detections = evaluate_detections(
        process
    )

    assert any(
        d["rule_id"] == "LC-R003"
        for d in detections
    )


def test_high_cpu_detection():

    process = base_process()
    process["cpu_percent"] = 95.0

    detections = evaluate_detections(
        process
    )

    assert any(
        d["rule_id"] == "LC-R004"
        for d in detections
    )


def test_network_detection():

    process = base_process()
    process["network_connections"] = 2

    detections = evaluate_detections(
        process
    )

    assert any(
        d["rule_id"] == "LC-R005"
        for d in detections
    )


def test_get_rule():

    rule = get_rule("LC-R004")

    assert rule is not None
    assert rule["name"] == "High Resource Utilization"
    assert rule["mitre_id"] == "T1496"

