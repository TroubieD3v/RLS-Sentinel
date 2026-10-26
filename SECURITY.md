# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** using GitHub's "Report a vulnerability" (private security advisory)
on this repository. Do not open a public issue for them. Include the version (`rls-sentinel version`), a description, and
steps to reproduce. You will get an acknowledgement; there is no guaranteed response time or bug bounty.

## Supported versions

Only the latest release receives fixes.

## Scope

In scope: the CLI, API and UI in this repository; anything that lets the tool write to or exfiltrate data from a database it
is only meant to read; secret leakage in logs, errors or reports; SSRF or allow-list bypass; authentication, CSRF or
DNS-rebinding bypass of the local API; injection through specs, fixtures or what-if drafts.

Out of scope: findings produced *about your own database* (that is the product's purpose), vulnerabilities in PostgreSQL or
third-party dependencies (report them upstream), and issues that require an attacker who already controls the host or a
trusted fixture (trusted fixtures run as superuser in the disposable server by design; see
[docs/threat-model.md](docs/threat-model.md)).

## Using the tool responsibly

Run it only against systems you are authorised to assess. See [docs/authorized-testing.md](docs/authorized-testing.md).
