# Contributing to OpenAPPA for Google Antigravity

Thank you for your interest in contributing to **openappa-antigravity**! We welcome contributions to policy rules, runtime engine enhancements, adapters, test replay suites, and documentation.

---

## Code of Conduct

All contributors and participants are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md).

---

## Development Setup

### Prerequisites

- Python 3.11 or higher
- Git

### Setting Up Your Environment

1. Clone the repository:
   ```bash
   git clone https://github.com/oliverowens/openappa-antigravity.git
   cd openappa-antigravity
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   # On Linux/macOS:
   source .venv/bin/activate
   # On Windows (PowerShell):
   .venv\Scripts\Activate.ps1
   ```

3. Install the package in editable mode with development dependencies:
   ```bash
   pip install --upgrade pip
   pip install -e .
   ```

---

## Verification & Testing

Before submitting a pull request, verify that all checks and tests pass locally:

### 1. Policy Validity Check
Verify that `policy/appa.toml` parses correctly and conforms to the OpenAPPA schema:
```bash
python appa.py describe --check
```

### 2. Deterministic Trace Replay
Run the deterministic event replay traces to ensure no trajectory regressions:
```bash
python appa.py replay policy-tests/
```

### 3. Automated Test Suite
Run the full test suite:
```bash
python -m unittest tests/test_suite.py
```

### 4. Code Formatting & Linting
Ensure code adheres to standard Python formatting conventions (4 spaces, clean imports, PEP 8).

---

## Pull Request Guidelines

1. **Branch Naming**: Use descriptive branch names such as `feature/my-feature` or `fix/issue-description`.
2. **Commit Messages**: Write concise, imperative commit messages (e.g. `feat: add remedy inspection command`, `fix: enforce workspace boundary check on relative paths`).
3. **Information-Flow Invariants**:
   - Never weaken the core Information-Flow Control algebra (`suspicious <= trusted`, `self <= internal <= public`).
   - Any new tool mapping must define explicit trust requirements and audience deltas in `policy/appa.toml`.
   - Tool execution must remain **fail-closed**: undeclared tools or runtime exceptions must deny execution and withhold sensitive outputs.
4. **Documentation**: Update `README.md` or `appa-package.toml` if introducing new CLI flags, policy selectors, or hooks.
