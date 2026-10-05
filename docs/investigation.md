```markdown
# LinuxCity Investigation Workflow

## Overview

LinuxCity is designed around an evidence-driven investigation workflow.

The objective is not simply to generate alerts.

The objective is to provide an analyst with enough context to answer:

```text
What happened?
Who executed it?
What executed?
How was it launched?
Why was it considered risky?
What detection rules triggered?
What ATT&CK techniques are relevant?
What should be investigated next?

```markdown
LinuxCity follows an evidence-driven investigation model.

```text
Alert  
  |  
  v
Process Identity
  |
  v
Behavior
  |
  v
Detection Rule
  |
  v
MITRE ATT&CK
  |
  v
Evidence
  |
  v
Analyst Investigation

