# Changelog

All notable changes to LinuxCity are documented here.

---

## [2.0.0] - 2026-10-06

### Added — Interactive Process City

- Redesigned LinuxCity around an interactive process-city concept.
- Processes are represented visually as security buildings.
- Building state reflects process risk and severity.
- Added process-focused visual investigation workflow.
- Added building selection and process inspection.
- Added visual distinction between LOW, MEDIUM, HIGH and CRITICAL activity.
- Added support for live process telemetry in the city visualization.
- Added process lifecycle event visualization.
- Added analyst-oriented process detail presentation.

### Added — Security Investigation Experience

- Process details now expose:
  - PID
  - PPID
  - Process name
  - Username
  - Parent process
  - Executable path
  - Command line
  - CPU usage
  - Memory usage
  - Network connections
  - Risk score
  - Severity
  - Detection rules
  - MITRE ATT&CK context
  - Risk reasoning
- Improved investigation workflow from process selection to security evidence.
- Persistent alert investigation remains available through the Investigation Center.

### Improved — SOC Dashboard

- Refined SOC dashboard layout.
- Improved process visualization.
- Improved alert presentation.
- Improved security event feed.
- Improved investigation panel.
- Improved responsive behavior.
- Improved visual distinction between security severity levels.
- Improved analyst-oriented information hierarchy.

### Improved — Documentation

- Reworked README as a portfolio-oriented project overview.
- Added Process City architecture explanation.
- Added investigation workflow documentation.
- Added detection engineering explanation.
- Added risk scoring explanation.
- Added API documentation.
- Added technology stack and roadmap sections.

### Security

- Continued use of localhost-only dashboard binding.
- Preserved explainable security scoring.
- Documented heuristic detection limitations.
- Clarified that MITRE ATT&CK mappings provide contextual references rather than definitive attribution.

---

## [1.0.0] - 2026-10-06

### Added

- Linux process monitoring.
- Process PID/PPID visibility.
- Username and process status collection.
- CPU and memory monitoring.
- Process parent information.
- Network connection visibility.
- Explainable 0–100 process risk scoring.
- Risk severity classification.
- Behavioral detection engine.
- MITRE ATT&CK contextual mappings.
- Persistent JSON security alerts.
- Alert deduplication.
- Investigation engine.
- Flask SOC dashboard.
- Process lifecycle event detection.
- REST APIs.
- Pytest test suite.
- GitHub Actions CI.

### Detection Rules

- LC-R001 — Root Process Execution
- LC-R002 — Suspicious Temporary Execution
- LC-R003 — Shell Spawned Process
- LC-R004 — High Resource Utilization
- LC-R005 — Network Active Process

---

## [0.6.0]

### Added

- Persistent alert storage.
- Alert severity classification.
- Alert evidence collection.
- Alert deduplication.
- Investigation generation.
- MITRE ATT&CK technique aggregation.
- Analyst notes field.

---

## [0.5.0]

### Added

- Detection engine.
- Detection rule IDs.
- MITRE ATT&CK contextual mapping.
- Security detection display in dashboard.

---

## [0.4.0]

### Added

- Explainable process risk scoring.
- Risk severity levels.
- Risk reasoning.
- Security-focused process details.

---

## [0.3.0]

### Added

- Process lifecycle monitoring.
- PROCESS_STARTED events.
- PROCESS_STOPPED events.
- Security event feed.

---

## [0.2.0]

### Added

- Flask SOC dashboard.
- Process visualization.
- Process detail panel.
- REST API endpoints.

---

## [0.1.0]

### Initial Release

- Linux process monitoring using psutil.
- Basic process telemetry.
- Process tree support.
- Initial Flask integration.
