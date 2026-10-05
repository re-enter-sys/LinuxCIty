
```markdown
# LinuxCity Detection Rules

## Overview

LinuxCity uses structured behavioral detection rules to identify process activity that may warrant security investigation.

The rules are intentionally explainable.

A detection indicates:

> "This behavior matches a security-relevant condition."

It does **not** automatically indicate:

> "This process is malicious."

Legitimate administrative and system processes may trigger some rules.

---

# Rule Catalog

| Rule ID | Name | Severity | ATT&CK |
|---|---|---|---|
| LC-R001 | Root Process Execution | MEDIUM | T1078 |
| LC-R002 | Suspicious Temporary Execution | HIGH | T1204 |
| LC-R003 | Shell Spawned Process | MEDIUM | T1059 |
| LC-R004 | High Resource Utilization | HIGH | T1496 |
| LC-R005 | Network Active Process | MEDIUM | T1071 |

---

# LC-R001 — Root Process Execution

## Purpose

Identifies processes executing with root privileges.

## Condition

```text
username == "root"
