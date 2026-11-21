# Security policy

## Reporting a vulnerability

Do not open a public issue for a security problem in this project.

Use GitHub private reporting: **Security → Report a vulnerability** on this repository.

Include:

- what you found and where,
- steps to reproduce,
- the impact you believe it has.

You will get an acknowledgement within a few days. Please give us a reasonable window to ship a fix before you disclose.

In scope: the runner (`lab/`), install scripts, recipe tooling, CI, and any recipe that weakens scope enforcement or leaks a credential.

Out of scope: vulnerabilities in the intentionally vulnerable lab targets (Juice Shop, DVWA and similar), and bugs in `sbx` itself. Report `sbx` issues to Docker.

## Acceptable use

This project is for defensive work and authorized testing.

- Test only targets you own or have written permission to test.
- Every security recipe needs a scope file. Do not remove or bypass it.
- Scope is enforced by `sbx` network policy. Do not weaken the policy to reach hosts outside the scope.
- No live malware in pull requests. Samples enter a sandbox at run time and the sandbox is destroyed after.
- Findings need proof. Do not file unproven claims as findings.
- Do not use recipes for denial of service, mass scanning, credential stuffing or attacks on third parties.

Maintainers may reject or remove any recipe that is offensive without a defensive purpose, that targets third parties, or that cannot be run inside a scope file.

Users are responsible for the legality of their own use.

## Supported versions

The project is pre-release. Only the `main` branch is supported.
