"""
LinuxCity Investigation Engine

Builds an investigation record from
a security alert and its observed evidence.
"""

from datetime import datetime


def build_investigation(alert):
    """
    Build a structured investigation record
    from a persistent security alert.
    """

    detections = alert.get("detections", [])

    mitre_techniques = []

    for detection in detections:
        technique = {
            "id": detection.get("mitre_id"),
            "name": detection.get("mitre_name"),
            "rule_id": detection.get("rule_id"),
        }

        if technique not in mitre_techniques:
            mitre_techniques.append(technique)

    evidence = {
        "pid": alert.get("pid"),
        "process_name": alert.get("process_name"),
        "username": alert.get("username"),
        "parent": alert.get("parent"),
        "executable": alert.get("exe", ""),
        "command_line": alert.get("cmdline", []),
        "cpu_percent": alert.get("cpu_percent", 0),
        "memory_percent": alert.get("memory_percent", 0),
        "network_connections": alert.get(
            "network_connections",
            0,
        ),
    }

    return {
        "investigation_id": (
            f"INV-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        ),
        "created_at": datetime.now().isoformat(),

        "alert_id": alert.get("alert_id"),
        "status": "NEW",

        "risk_score": alert.get(
            "risk_score",
            0,
        ),
        "severity": alert.get(
            "severity",
            "UNKNOWN",
        ),

        "detection_count": len(
            detections
        ),

        "detections": detections,

        "mitre_techniques": mitre_techniques,

        "evidence": evidence,

        "analyst_notes": "",
    }
