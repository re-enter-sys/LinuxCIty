"""
LinuxCity Detection Engine

Maps observable process behaviors to
security detection rules and MITRE ATT&CK techniques.
"""


DETECTION_RULES = [

    {
        "rule_id": "LC-R001",
        "name": "Root Process Execution",
        "description": "Process is executing with root privileges.",
        "mitre_id": "T1078",
        "mitre_name": "Valid Accounts",
        "severity": "MEDIUM",
        "condition": "root",
    },

    {
        "rule_id": "LC-R002",
        "name": "Suspicious Temporary Execution",
        "description": "Executable is running from a temporary location.",
        "mitre_id": "T1204",
        "mitre_name": "User Execution",
        "severity": "HIGH",
        "condition": "temporary_path",
    },

    {
        "rule_id": "LC-R003",
        "name": "Shell Spawned Process",
        "description": "Process was launched from an interactive shell.",
        "mitre_id": "T1059",
        "mitre_name": "Command and Scripting Interpreter",
        "severity": "MEDIUM",
        "condition": "shell_parent",
    },

    {
        "rule_id": "LC-R004",
        "name": "High Resource Utilization",
        "description": "Process is consuming unusually high CPU resources.",
        "mitre_id": "T1496",
        "mitre_name": "Resource Hijacking",
        "severity": "HIGH",
        "condition": "high_cpu",
    },

    {
        "rule_id": "LC-R005",
        "name": "Network Active Process",
        "description": "Process currently has active network connections.",
        "mitre_id": "T1071",
        "mitre_name": "Application Layer Protocol",
        "severity": "MEDIUM",
        "condition": "network",
    },

]


def evaluate_detections(process):
    """
    Evaluate a process against LinuxCity detection rules.

    Returns a list of triggered detection rules.
    """

    detections = []

    if process["username"] == "root":
        detections.append(
            get_rule("LC-R001")
        )

    exe = process.get("exe") or ""

    if exe.startswith(
        ("/tmp/", "/var/tmp/", "/dev/shm/")
    ):
        detections.append(
            get_rule("LC-R002")
        )

    if process["parent"] in (
        "bash",
        "sh",
        "zsh",
    ):
        detections.append(
            get_rule("LC-R003")
        )

    if process["cpu_percent"] >= 80:
        detections.append(
            get_rule("LC-R004")
        )

    if process["network_connections"] > 0:
        detections.append(
            get_rule("LC-R005")
        )

    return detections


def get_rule(rule_id):
    """Return a detection rule by ID."""

    for rule in DETECTION_RULES:

        if rule["rule_id"] == rule_id:
            return rule.copy()

    return None
