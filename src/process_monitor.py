import psutil
from datetime import datetime


PROCESS_FIELDS = [
    "pid",
    "ppid",
    "name",
    "username",
    "status",
    "cpu_percent",
    "memory_percent",
]


def get_processes():
    """Collect information about currently running processes."""

    processes = []

    for proc in psutil.process_iter(PROCESS_FIELDS):
        try:
            info = proc.info

            processes.append({
                "pid": info["pid"],
                "ppid": info["ppid"],
                "name": info["name"] or "unknown",
                "username": info["username"] or "unknown",
                "status": info["status"] or "unknown",
                "cpu_percent": info["cpu_percent"] or 0.0,
                "memory_percent": info["memory_percent"] or 0.0,
            })

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            continue

    return processes


def build_process_tree(processes):
    """Build a parent PID -> child process mapping."""

    tree = {}

    for process in processes:
        ppid = process["ppid"]

        if ppid not in tree:
            tree[ppid] = []

        tree[ppid].append(process)

    return tree


def get_process_map(processes):
    """Create a PID -> process mapping."""

    return {
        process["pid"]: process
        for process in processes
    }


def detect_process_events(previous, current):
    """
    Detect processes that appeared or disappeared
    between two snapshots.
    """

    previous_map = get_process_map(previous)
    current_map = get_process_map(current)

    previous_pids = set(previous_map)
    current_pids = set(current_map)

    started_pids = current_pids - previous_pids
    stopped_pids = previous_pids - current_pids

    events = []

    for pid in sorted(started_pids):
        process = current_map[pid]

        events.append({
            "type": "PROCESS_STARTED",
            "timestamp": datetime.now().isoformat(),
            "pid": pid,
            "name": process["name"],
            "ppid": process["ppid"],
        })

    for pid in sorted(stopped_pids):
        process = previous_map[pid]

        events.append({
            "type": "PROCESS_STOPPED",
            "timestamp": datetime.now().isoformat(),
            "pid": pid,
            "name": process["name"],
            "ppid": process["ppid"],
        })

    return events


def create_snapshot():
    """Create a timestamped process snapshot."""

    return {
        "timestamp": datetime.now().isoformat(),
        "processes": get_processes(),
    }
