# Security Policy

## Supported Versions

We actively support and provide security updates for the following versions of `openappa-antigravity`:

| Version | Supported          |
| :---    | :---               |
| 0.3.x   | :white_check_mark: |
| < 0.3.0 | :x:                |

---

## Reporting a Vulnerability

As an Information-Flow Control (IFC) and security runtime, we treat security vulnerabilities with the highest priority. If you believe you have discovered a vulnerability in `openappa-antigravity`—including policy bypasses, information disclosure bugs, or execution control flaws—please report it responsibly.

### How to Report

1. **GitHub Private Vulnerability Reporting (Preferred)**:
   Navigate to the **Security** tab of the repository on GitHub and select **Report a vulnerability** to submit a private advisory directly to the maintainers.

2. **Security Contact**:
   If private vulnerability reporting is unavailable, contact Oliver Owens via GitHub:
   [https://github.com/oliverowens](https://github.com/oliverowens)

Please do **NOT** open public issues or PRs discussing unpatched security vulnerabilities.

### What to Include

To help us triage and reproduce the issue quickly, please include:
- A detailed description of the suspected vulnerability.
- Minimal reproducible example or policy configuration (`policy/appa.toml`).
- Tool call sequence or trajectory replay demonstrating the unexpected behavior.
- The expected vs. actual behavior under Information-Flow Control.
- Any proposed remediation, if known.

### Response & Disclosure Process

- **Acknowledgement**: We aim to acknowledge vulnerability reports within 48 hours.
- **Triage & Patching**: We will assess the severity, reproduce the issue, and prepare a fix.
- **Disclosure**: Once a patch is released (typically as a patch release tag `v0.3.x`), we will publish a security advisory giving appropriate credit to the reporter.
