# Contributing to SNI-Spoofing

Thank you for contributing to **SNI-Spoofing**.

This project is a Windows-focused networking research tool. Contributions should prioritize correctness, maintainability, testability, and safe use.

## Before You Start

1. Read the [README](README.md) and [Security Policy](SECURITY.md).
2. Search existing issues and pull requests before opening a new one.
3. Keep changes focused. Avoid unrelated refactors in feature or bug-fix PRs.
4. Never commit credentials, private keys, captured traffic, or personal data.

## Development Setup

The supported development range is Python 3.10–3.12.

```powershell
py -3.12 -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Tests

The repository uses Python's built-in `unittest` runner so the parser/configuration tests can run without the WinDivert driver:

```powershell
python -m unittest discover -s tests -v
```

Changes to packet parsing, configuration validation, or connection lifecycle code should include regression tests where practical.

The full runtime path depends on Windows and WinDivert, so local unit-test success does not by itself prove end-to-end packet interception works.

## Pull Requests

Please include:

- A clear problem statement.
- A short explanation of the implementation.
- Tests added or updated, when applicable.
- Documentation updates for user-visible behavior or configuration changes.
- Any platform or privilege requirements.

Use **Conventional Commits**, for example:

```text
fix: handle malformed ClientHello input
test: add ClientHello round-trip coverage
docs: update supported Python versions
ci: add unit test workflow
```

## Security

Do not publish sensitive vulnerability details in a normal issue or pull request. Follow [SECURITY.md](SECURITY.md) for private disclosure.

Only use the project on systems and networks where you have authorization to test.

## License

By contributing, you agree that your contributions are provided under the repository's MIT License.
