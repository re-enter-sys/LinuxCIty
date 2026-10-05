# Security Policy

## Purpose

LinuxCity is a local Linux security monitoring and investigation project created for cybersecurity education, security engineering practice and defensive monitoring research.

---

## Scope

The project focuses on:

- Linux process monitoring
- Behavioral detection
- Risk scoring
- Security alerting
- MITRE ATT&CK mapping
- Security investigation workflows

---

## Safe Usage

LinuxCity should be used on systems that the operator owns or is explicitly authorized to monitor.

Do not deploy the project against systems without authorization.

---

## Dashboard Security

The Flask dashboard is configured to bind to:

```text
127.0.0.1
