# Contributing

Thanks for your interest in improving this **Strix Advanced Tools** project! Contributions of
all kinds are welcome: bug reports, documentation, translations, and code.

## Ground rules

- **Security first.** These are security/privacy tools. Preserve the existing guarantees:
  no network, no shell (use argument lists for subprocesses), no dynamic code
  (`eval`/`exec`/`pickle`), input validation, and least privilege. If a change touches a
  security-relevant path, add or update a test and explain the reasoning.
- **Keep dependencies few and vetted.** Prefer the standard library and mature, audited
  components over new third-party packages.
- **Cross-platform.** Keep Windows and Linux behavior in sync; guard platform-specific
  code and degrade gracefully.

## Development

1. Fork and clone the repo.
2. Run the app from source (see the README).
3. Run the test suite before opening a PR (see `tests/`).
4. Match the surrounding code style; keep functions small and readable.

## Reporting bugs

Open an issue using the templates in `.github/ISSUE_TEMPLATE/`. Include your OS, how you
installed, exact steps to reproduce, and what you expected.

## Security issues

**Do not** file security vulnerabilities as public issues — see [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions are licensed under the project's
[MIT License](LICENSE).
