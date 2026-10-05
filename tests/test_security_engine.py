from security_engine import calculate_risk


def test_normal_process_has_low_risk():
    process = {
        "pid": 100,
        "name": "bash",
        "username": "viswa",
        "exe": "/usr/bin/bash",
        "cmdline": ["bash"],
        "cpu_percent": 1.0,
        "memory_percent": 1.0,
        "network_connections": 0,
        "parent": "systemd",
    }

    result = calculate_risk(process)

    assert result["score"] < 50
    assert result["severity"] in ("LOW", "MEDIUM")


def test_root_process_increases_risk():
    process = {
        "pid": 200,
        "name": "python3",
        "username": "root",
        "exe": "/usr/bin/python3",
        "cmdline": ["python3"],
        "cpu_percent": 1.0,
        "memory_percent": 1.0,
        "network_connections": 0,
        "parent": "systemd",
    }

    result = calculate_risk(process)

    assert result["score"] >= 20
    assert "Process is running as root" in result["reasons"]


def test_suspicious_path_increases_risk():
    process = {
        "pid": 300,
        "name": "payload",
        "username": "viswa",
        "exe": "/tmp/payload",
        "cmdline": ["/tmp/payload"],
        "cpu_percent": 1.0,
        "memory_percent": 1.0,
        "network_connections": 0,
        "parent": "systemd",
    }

    result = calculate_risk(process)

    assert result["score"] >= 30
    assert any("suspicious" in reason.lower() for reason in result["reasons"])


def test_high_cpu_increases_risk():
    process = {
        "pid": 400,
        "name": "worker",
        "username": "viswa",
        "exe": "/usr/bin/worker",
        "cmdline": ["worker"],
        "cpu_percent": 95.0,
        "memory_percent": 2.0,
        "network_connections": 0,
        "parent": "systemd",
    }

    result = calculate_risk(process)

    assert result["score"] >= 20
    assert "High CPU utilization" in result["reasons"]


def test_network_process_increases_risk():
    process = {
        "pid": 500,
        "name": "python3",
        "username": "viswa",
        "exe": "/usr/bin/python3",
        "cmdline": ["python3"],
        "cpu_percent": 1.0,
        "memory_percent": 2.0,
        "network_connections": 3,
        "parent": "systemd",
    }

    result = calculate_risk(process)

    assert result["score"] >= 10
    assert "Process has active network connections" in result["reasons"]
