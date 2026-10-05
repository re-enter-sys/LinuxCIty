import json
import os
from datetime import datetime


BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

ALERT_FILE = os.path.join(
    BASE_DIR,
    "data",
    "alerts.json",
)


def ensure_alert_file():
    os.makedirs(
        os.path.dirname(ALERT_FILE),
        exist_ok=True,
    )

    if not os.path.exists(ALERT_FILE):
        with open(
            ALERT_FILE,
            "w",
            encoding="utf-8",
        ) as file:
            json.dump([], file, indent=2)


def load_alerts():
    ensure_alert_file()

    try:
        with open(
            ALERT_FILE,
            "r",
            encoding="utf-8",
        ) as file:
            return json.load(file)

    except (
        json.JSONDecodeError,
        OSError,
    ):
        return []


def save_alerts(alerts):
    ensure_alert_file()

    with open(
        ALERT_FILE,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            alerts,
            file,
            indent=2,
        )


def create_alert(process, risk, detections=None):
    """
    Create a persistent security alert.

    Duplicate OPEN alerts for the same PID
    and severity are prevented.
    """

    alerts = load_alerts()

    for existing in alerts:

        if (
            existing["pid"] == process["pid"]
            and existing["status"] == "OPEN"
            and existing["severity"] == risk["severity"]
        ):
            return existing

    detections = detections or []

    now = datetime.now().isoformat()

    alert = {
        "alert_id": (
            f"LC-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        ),
        "timestamp": now,

        "pid": process["pid"],
        "process_name": process["name"],
        "username": process["username"],
        "parent": process["parent"],

        "exe": process.get("exe", ""),
        "cmdline": process.get("cmdline", []),

        "cpu_percent": process["cpu_percent"],
        "memory_percent": process["memory_percent"],
        "network_connections": process[
            "network_connections"
        ],

        "risk_score": risk["score"],
        "severity": risk["severity"],
        "reasons": risk["reasons"],

        "detections": detections,

        "status": "OPEN",
    }

    alerts.append(alert)
    save_alerts(alerts)

    return alert
