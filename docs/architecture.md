# LinuxCity Architecture

## Overview

LinuxCity is a local Linux security monitoring and investigation platform.

It continuously collects running-process information, evaluates observable behavior, calculates an explainable risk score, maps detected behaviors to MITRE ATT&CK techniques, creates persistent security alerts, and provides investigation evidence through a Flask SOC dashboard.

## Architecture

```text
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
