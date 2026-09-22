# SECURITY.md — Reporting a vulnerability in this repository

This file is about the **repository itself** (the code in this repo), not about
how the tools are used. For responsible use of the capabilities in this repo,
please follow [ETHICS.md](ETHICS.md) and [SCOPE.md](SCOPE.md).

## Reporting

Please **do not** open a public issue for vulnerabilities. Instead, email
`5h4d0wn1k@users.noreply.github.com` with:

- a short description of the issue (code execution, injection, secrets exposure,
  broken sandboxing/safety gating, etc.),
- affected file/command and steps to reproduce,
- a suggested fix (optional but appreciated).

## Disclosure timeline

| Step | Target |
|------|--------|
| Acknowledgement | within 72 hours of the report |
| Triage (reproduction + severity) | report status updated within 5 business days |
| Fix + coordinated release | before or together with a public advisory |

If you reported a reproducible issue and it reaches 90 days unremediated, you are
free to disclose publicly after that point, with acknowledgement of this project.

## Scope

In scope: source code, build scripts, workflows, and runtime behavior of this
repository.

Out of scope: use of this software against systems you do not own or hold
explicit written authorization to assess.