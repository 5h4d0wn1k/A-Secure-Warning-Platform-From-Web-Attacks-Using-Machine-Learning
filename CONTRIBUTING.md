# Contributing to A-Secure-Warning-Platform-From-Web-Attacks-Using-Machine-Learning

Thanks for your interest! This project is **educational and defensive** software
for authorized, responsible security practice — see [ETHICS.md](ETHICS.md) and
[SCOPE.md](SCOPE.md). Contributions should respect that intent.

## Ground rules

- **Educational purpose only.** No code or docs that target systems the user
  does not own or have explicit written authorization to test.
- **Safety by default.** Prefer dry-run/offline/lab defaults; call out any mode
  that enables network or real-target behavior.
- **Quality.** Keep tests green (`pytest`/`cargo test` as the repo already
  defines). No secret keys, tokens, or personal data in commits.

## Steps

1. Fork the repository and create a branch:
   `git checkout -b feature/your-change`
2. Make the change with tests where practical.
3. Run the existing test suite and linters.
4. Commit with a clear message and open a pull request referencing any issue.

## Pull request checklist

- [ ] Change follows project intent (educational/defensive, authorized-only)
- [ ] Tests pass
- [ ] README/docs updated if behavior changed
- [ ] No secrets or credentials in the diff

## Reporting vulnerabilities

See [SECURITY.md](SECURITY.md) — report privately, not in a public issue.