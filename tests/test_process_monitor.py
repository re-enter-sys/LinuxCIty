from process_monitor import (
    get_processes,
    build_process_tree,
    detect_process_events,
)


def test_get_processes_returns_list():
    processes = get_processes()

    assert isinstance(processes, list)
    assert len(processes) > 0


def test_process_has_required_fields():
    processes = get_processes()

    required_fields = {
        "pid",
        "ppid",
        "name",
        "username",
        "status",
        "cpu_percent",
        "memory_percent",
    }

    for process in processes:
        assert required_fields.issubset(process.keys())


def test_process_tree():
    processes = [
        {
            "pid": 1,
            "ppid": 0,
            "name": "init",
            "username": "root",
            "status": "running",
            "cpu_percent": 0,
            "memory_percent": 0,
        },
        {
            "pid": 2,
            "ppid": 1,
            "name": "bash",
            "username": "user",
            "status": "running",
            "cpu_percent": 0,
            "memory_percent": 0,
        },
    ]

    tree = build_process_tree(processes)

    assert 0 in tree
    assert 1 in tree
    assert tree[0][0]["pid"] == 1
    assert tree[1][0]["pid"] == 2


def test_process_started_event():
    previous = [
        {
            "pid": 1,
            "ppid": 0,
            "name": "init",
        }
    ]

    current = [
        {
            "pid": 1,
            "ppid": 0,
            "name": "init",
        },
        {
            "pid": 100,
            "ppid": 1,
            "name": "python3",
        },
    ]

    events = detect_process_events(previous, current)

    assert len(events) == 1
    assert events[0]["type"] == "PROCESS_STARTED"
    assert events[0]["pid"] == 100
    assert events[0]["name"] == "python3"


def test_process_stopped_event():
    previous = [
        {
            "pid": 1,
            "ppid": 0,
            "name": "init",
        },
        {
            "pid": 100,
            "ppid": 1,
            "name": "python3",
        },
    ]

    current = [
        {
            "pid": 1,
            "ppid": 0,
            "name": "init",
        }
    ]

    events = detect_process_events(previous, current)

    assert len(events) == 1
    assert events[0]["type"] == "PROCESS_STOPPED"
    assert events[0]["pid"] == 100
    assert events[0]["name"] == "python3"
