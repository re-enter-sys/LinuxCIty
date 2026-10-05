## 🖥️ LinuxCity in Action

### SOC Dashboard

/home/killerg/projects/LinuxCity/screenshots/Dashboard.png

### Process Investigation

/home/killerg/projects/LinuxCity/screenshots/Investigation Centre.png

### Security Alerts

/home/killerg/projects/LinuxCity/screenshots/Security Events.png


### Local Linux Security Monitoring & Investigation Platform

LinuxCity transforms a running Linux system into a live security monitoring environment.

It continuously analyzes running processes, evaluates observable behavior, calculates explainable risk scores, applies security detection rules, maps relevant behaviors to MITRE ATT&CK techniques, generates persistent security alerts, and presents the results through a SOC-style web dashboard.

---

## 🚀 Features

- Live Linux process monitoring
- Parent/child process visibility
- CPU and memory monitoring
- Process start/stop event detection
- Explainable security risk scoring
- Suspicious execution-path detection
- Root-process detection
- Shell-launched process detection
- High CPU detection
- Network-active process detection
- MITRE ATT&CK technique mapping
- Persistent security alerts
- Duplicate alert prevention
- Investigation records
- Process evidence collection
- SOC-style Flask dashboard
- Local-only dashboard by default
- Automated GitHub Actions CI

---

## 🧠 Detection Pipeline

```text
Linux Process
      ↓
Process Monitoring
      ↓
Security Analysis
      ↓
Behavior Detection
      ↓
Detection Rules
      ↓
MITRE ATT&CK Mapping
      ↓
Risk Scoring
      ↓
Security Alert
      ↓
Investigation
      ↓
Evidence
      ↓
SOC Dashboard


##  ARCHITECTURE

                         ┌──────────────────────┐
                         │      Linux Host      │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │   Process Monitor    │
                         │                      │
                         │ PID / PPID           │
                         │ User                 │
                         │ CPU / Memory         │
                         │ Process Events       │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │   Security Engine    │
                         │                      │
                         │ Process Details      │
                         │ Risk Score            │
                         │ Risk Reasoning        │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │  Detection Engine    │
                         │                      │
                         │ LC-R001 ... LC-R005 │
                         │ Severity             │
                         │ MITRE ATT&CK         │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │    Alert Engine      │
                         │                      │
                         │ Persistent Alerts    │
                         │ Deduplication        │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │ Investigation Engine │
                         │                      │
                         │ Evidence             │
                         │ Detections           │
                         │ ATT&CK Techniques    │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │   Flask SOC UI       │
                         │                      │
                         │ Process City         │
                         │ Events               │
                         │ Alerts               │
                         │ Investigation Center │
                         └──────────────────────┘
