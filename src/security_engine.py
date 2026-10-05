import os
import psutil


SUSPICIOUS_PATHS = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
)


def get_process_details(pid):
    """Collect security-relevant details for a process."""

    try:
        proc = psutil.Process(pid)

        with proc.oneshot():
            username = proc.username()
            name = proc.name()
            exe = proc.exe()
            cmdline = proc.cmdline()
            cpu = proc.cpu_percent(interval=0.1)
            memory = proc.memory_percent()

            try:
                connections = proc.net_connections()
                network_count = len(connections)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                network_count = 0

            try:
                parent = proc.parent()
                parent_name = parent.name() if parent else "unknown"
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                parent_name = "unknown"

        return {
            "pid": pid,
            "name": name,
            "username": username,
            "exe": exe,
            "cmdline": cmdline,
            "cpu_percent": cpu,
            "memory_percent": memory,
            "network_connections": network_count,
            "parent": parent_name,
        }

    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess,
    ):
        return None


def calculate_risk(process):
    """Calculate a simple explainable process risk score."""

    if not process:
        return {
            "score": 0,
            "severity": "UNKNOWN",
            "reasons": [],
        }

    score = 0
    reasons = []

    username = process["username"]
    exe = process["exe"]
    cpu = process["cpu_percent"]
    network = process["network_connections"]
    parent = process["parent"]

    # Root execution
    if username == "root":
        score += 20
        reasons.append("Process is running as root")

    # Suspicious execution locations
    if exe and exe.startswith(SUSPICIOUS_PATHS):
        score += 30
        reasons.append("Executable is running from a suspicious temporary location")

    # High CPU
    if cpu >= 80:
        score += 20
        reasons.append("High CPU utilization")

    # Network activity
    if network > 0:
        score += 10
        reasons.append("Process has active network connections")

    # Potentially interesting parent
    if parent in ("bash", "sh", "zsh"):
        score += 10
        reasons.append("Process was launched from a shell")

    score = min(score, 100)

    if score >= 75:
        severity = "CRITICAL"
    elif score >= 50:
        severity = "HIGH"
    elif score >= 25:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "score": score,
        "severity": severity,
        "reasons": reasons,
    }
