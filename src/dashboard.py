from datetime import datetime

from flask import Flask, jsonify, render_template

from process_monitor import get_processes, detect_process_events
from security_engine import get_process_details, calculate_risk
from detection_engine import evaluate_detections
from alert_engine import create_alert, load_alerts
from investigation_engine import build_investigation


app = Flask(__name__)

previous_processes = []


def collect_dashboard_data():
    processes = get_processes()
    results = []

    for process in processes:
        details = get_process_details(process["pid"])

        if not details:
            continue

        risk = calculate_risk(details)
        detections = evaluate_detections(details)

        results.append({
            "pid": details["pid"],
            "ppid": process.get("ppid", 0),
            "name": details["name"],
            "username": details["username"],
            "exe": details.get("exe", ""),
            "cmdline": details.get("cmdline", []),
            "cpu_percent": round(details["cpu_percent"], 1),
            "memory_percent": round(details["memory_percent"], 1),
            "network_connections": details["network_connections"],
            "parent": details["parent"],
            "risk_score": risk["score"],
            "severity": risk["severity"],
            "reasons": risk["reasons"],
            "detections": detections,
        })

    results.sort(
        key=lambda process: process["risk_score"],
        reverse=True,
    )

    return results


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/processes")
def processes_api():
    processes = collect_dashboard_data()

    return jsonify({
        "count": len(processes),
        "processes": processes,
    })


@app.route("/api/city")
def city_api():
    global previous_processes

    processes = collect_dashboard_data()

    events = detect_process_events(
        previous_processes,
        processes,
    )

    alerts = []

    for process in processes:
        if process["risk_score"] >= 50:
            risk = {
                "score": process["risk_score"],
                "severity": process["severity"],
                "reasons": process["reasons"],
            }

            alert = create_alert(
                process,
                risk,
                process.get("detections", []),
            )

            alerts.append(alert)

    previous_processes = processes

    return jsonify({
        "processes": processes,
        "events": events,
        "alerts": alerts,
        "timestamp": datetime.now().isoformat(),
    })


@app.route("/api/alerts")
def alerts_api():
    alerts = load_alerts()

    return jsonify({
        "count": len(alerts),
        "alerts": alerts,
    })


@app.route("/api/investigations/<alert_id>")
def investigation_api(alert_id):
    alerts = load_alerts()

    for alert in alerts:
        if alert.get("alert_id") == alert_id:
            return jsonify(
                build_investigation(alert)
            )

    return jsonify({
        "error": "Alert not found"
    }), 404


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )
