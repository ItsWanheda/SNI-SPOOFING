# Contributing to Spectra Scan

Welcome to Spectra Scan! We are thrilled that you're interested in contributing to our mission of building a professional, Go-based network security research tool.

By contributing to this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### 1. Issues and Bug Reports
- **Search first:** Before opening a new issue, check if it has already been reported.
- **Use templates:** Use the provided issue templates for bugs, feature requests, or security discussions.
- **Be clear:** Provide as much detail as possible (logs, Go version, OS, reproduction steps).

### 2. Pull Requests
We follow a standard professional workflow. All contributions must go through the Pull Request (PR) process.

#### Development Workflow
1. **Fork** the repository and create your feature branch: `git checkout -b feat/your-feature-name`.
2. **Follow Go standards:**
   - Run `go fmt ./...` before committing.
   - Ensure all code passes `go vet` and `staticcheck`.
3. **Tests are mandatory:**
   - All new features and bug fixes **must** include unit tests.
   - Run `go test ./...` to ensure no regressions.
4. **Conventional Commits:** We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:
   - `feat:` for new features
   - `fix:` for bug fixes
   - `docs:` for changes to documentation
   - `refactor:` for code changes that neither fix a bug nor add a feature
   - `test:` for adding missing tests

#### Security-First Development
Since Spectra Scan is a security tool, please adhere to these rules:
- **No Hardcoded Secrets:** Never include API keys, passwords, or tokens in your code.
- **Memory Safety:** When dealing with network buffers or raw packets, be mindful of potential buffer overflows.
- **Input Validation:** Always sanitize inputs. If your feature handles user-provided URLs or IPs, ensure it is protected against **SSRF** and **Injection** attacks.
- **No Malicious Payloads:** Do not include or suggest payloads that could be used for malicious exploitation in the codebase. We focus on detection and analysis.

### 3. Review Process
- Maintainers will review your code. We prioritize readability, maintainability, and security.
- Be prepared to answer questions or make changes based on the review.
- Once approved, your PR will be merged.

### 4. License
By submitting a pull request, you agree that your contributions will be licensed under the project's license (to be added).

---
*Happy Hacking, and thank you for helping make the network safer!*
