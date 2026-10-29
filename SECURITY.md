# Security policy

This project is security software that is deliberately exposed to hostile
traffic, so vulnerability reports are taken seriously.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Use GitHub's private vulnerability reporting: *Security* tab -> *Report a
vulnerability* on this repository. Include:

* the affected version / commit (`honeypot -version`),
* a description of the impact (what can an unauthenticated remote client do?),
* a minimal reproduction (a packet capture, a Go test, or a script).

You can expect an acknowledgement within 7 days and a fix or mitigation plan
within 30 days. Reporters are credited in the changelog unless they prefer
otherwise.

## What is in scope

The honeypot's trust boundary is the network socket: every byte a client sends
is hostile. The following are considered vulnerabilities:

* remote code execution, or any path by which attacker input is executed,
  interpreted by a real shell, or used to spawn a process;
* memory exhaustion, unbounded CPU use, goroutine or file-descriptor leaks
  reachable from a single unauthenticated connection (denial of service beyond
  the documented limits);
* SSRF / protection bypass in the payload downloader (reaching loopback,
  link-local, private or metadata addresses, or following a redirect into one);
* path traversal or overwriting of files outside `HP_PAYLOAD_DIR` / `HP_LOG_DIR`;
* injection into the Telegram message, the JSONL log, the SQLite loader or the
  Prometheus endpoint (e.g. unescaped attacker-controlled text);
* secrets leaking into logs, alerts or the container image;
* bypass of the storage quota, per-file cap or per-session caps.

## What is out of scope

* The honeypot being *detectable* as a honeypot. It is a low-interaction
  sensor; fingerprintability is documented in the [technical report](docs/TECHNICAL_REPORT.md) (section 13).
* Findings that require control of the operator's host, environment or
  `.env` file.
* Malware samples that the honeypot has captured (they are, by design,
  malicious).

## Supported versions

Only the latest release and the `main` branch receive security fixes.

## Operator hardening

Deployment guidance (egress firewall, isolated VLAN, read-only root file
system, non-root user) is in the [technical report](docs/TECHNICAL_REPORT.md), section 8. Captured samples are live
malware: never execute them on a machine you care about.
