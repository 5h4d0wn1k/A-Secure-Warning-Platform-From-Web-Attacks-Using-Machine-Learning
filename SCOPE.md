# SCOPE.md — Scope-checker for authorized testing

Before you run **A-Secure-Warning-Platform-From-Web-Attacks-Using-Machine-Learning** against any live target, answer these four questions.
Write the answers down. If you cannot answer "YES" to all four, **stop** — build
a lab instead.

| # | Question | Acceptable answer |
|---|---|---|
| 1 | **Who owns the target?** Is it your hardware, your network, your cloud account, your code? | YES — I control it |
| 2 | **Do you have written permission?** Signed scope doc, bug-bounty program rules, employer authorization? | YES — written, current, bounded |
| 3 | **What is the blast radius?** What breaks if an action goes wrong? Production? Client data? | YES — I've identified it and accepted it |
| 4 | **When does it end?** Time-boxed? Can you fully undo/clean up your testing? | YES — start/end defined |

## Lab path instead

If any answer is NO or unknown, stay in the lab:

- Your own VM or laptop → OS, malware, exploitation, forensics
- `localhost` services and disposable containers → web/app/network
- Your own router/AP, a second radio you own → wireless/network testing
- PII, HIPAA, or systems you don't control → **out of scope, always**

## Reporting an accidental hit

If you find a real vulnerability on a third party while testing an authorized
parent engagement:

1. Stop that specific test.
2. Report privately to the system owner, with timestamps and no PoC code reuse.
3. Follow the engagement's disclosure rules (usually coordinated disclosure).
4. Never publish without permission.

---

This checklist is the *operational* half of [ETHICS.md](ETHICS.md). The project
stays legal and useful because the user stays scoped.