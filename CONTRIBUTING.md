# Contributing to Biceps-Check

Thank you for your interest in contributing to Biceps-Check! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Adding New Rules](#adding-new-rules)
- [Testing](#testing)
- [Code Style](#code-style)
- [Pull Request Process](#pull-request-process)
- [Reporting Issues](#reporting-issues)

## Code of Conduct

This project adheres to a Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the maintainers.

## Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/biceps-check.git
   cd biceps-check
   ```
3. Add the upstream remote:
   ```bash
   git remote add upstream https://github.com/your-org/biceps-check.git
   ```

## Development Setup

### Prerequisites

- Python 3.10 or higher
- pip or pipx for package management

### Installation

1. Create a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

2. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

3. Install pre-commit hooks:
   ```bash
   pre-commit install
   ```

### Running the Tool Locally

```bash
# Run from source
python -m biceps_check.cli scan ./examples

# Or after installing
biceps-check scan ./examples
```

## Adding New Rules

Rules are the core of Biceps-Check. Each rule checks for a specific security configuration.

### Rule Structure

Create a new rule in the appropriate category under `src/biceps_check/checks/`:

```python
from biceps_check.parser.models import BicepResource
from biceps_check.rules.base import BaseRule, RuleResult, Severity


class MyNewRule(BaseRule):
    """Check description."""

    # Required attributes
    id = "BCK_AZURE_XX_001"  # Unique ID
    name = "Human-readable rule name"
    description = "Detailed description of what the rule checks and why it matters."
    severity = Severity.HIGH  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    resource_types = ["Microsoft.Resource/type"]  # Azure resource types
    category = "category_name"  # compute, storage, networking, etc.
    remediation = "How to fix this issue."
    references = [
        "https://docs.microsoft.com/...",
    ]

    # Optional compliance mappings
    cis_azure = ["1.2.3"]
    nist_800_53 = ["SC-8"]
    pci_dss = ["4.1"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Execute the check."""
        value = resource.get_property("properties.someProperty")

        if value is not True:
            return RuleResult.FAILED

        return RuleResult.PASSED
```

### Rule ID Convention

Rule IDs follow the pattern: `BCK_AZURE_{CATEGORY}_{NUMBER}`

| Category | Abbreviation |
|----------|--------------|
| Virtual Machines | VM |
| VM Scale Sets | VMSS |
| App Service | APP |
| Functions | FUNC |
| Storage Account | ST |
| Key Vault | KV |
| NSG | NSG |
| SQL Server | SQL |
| Cosmos DB | COSMOS |
| AKS | AKS |
| ... | ... |

### Rule Testing Requirements

Every rule must have:

1. **Unit tests** with passing and failing cases
2. **Example Bicep files** (compliant and non-compliant)
3. **Documentation** in the rule catalog

Example test file:

```python
# tests/unit/test_rules_myresource.py
import pytest
from biceps_check.checks.category.myresource import MyNewRule
from biceps_check.parser.models import BicepResource
from biceps_check.rules.base import RuleResult


class TestMyNewRule:
    """Tests for BCK_AZURE_XX_001."""

    def test_pass_when_compliant(self):
        """Should pass when properly configured."""
        resource = BicepResource(
            name="test",
            resource_type="Microsoft.Resource/type",
            api_version="2023-01-01",
            properties={"properties": {"someProperty": True}},
            line_number=1,
        )
        rule = MyNewRule()
        assert rule.check(resource) == RuleResult.PASSED

    def test_fail_when_misconfigured(self):
        """Should fail when misconfigured."""
        resource = BicepResource(
            name="test",
            resource_type="Microsoft.Resource/type",
            api_version="2023-01-01",
            properties={"properties": {"someProperty": False}},
            line_number=1,
        )
        rule = MyNewRule()
        assert rule.check(resource) == RuleResult.FAILED
```

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=biceps_check --cov-report=html

# Run specific test file
pytest tests/unit/test_rules_storage.py

# Run tests matching pattern
pytest -k "storage"
```

### Test Structure

```
tests/
├── unit/           # Unit tests for individual components
├── integration/    # Integration tests for full workflows
└── fixtures/       # Test data and fixtures
```

## Code Style

We use several tools to maintain code quality:

- **Black**: Code formatting
- **isort**: Import sorting
- **Ruff**: Linting
- **mypy**: Type checking

### Running Linters

```bash
# Format code
black src tests
isort src tests

# Run linter
ruff check src tests

# Type check
mypy src
```

### Pre-commit Hooks

Pre-commit hooks run automatically on `git commit`. To run manually:

```bash
pre-commit run --all-files
```

## Pull Request Process

1. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/my-feature
   ```

2. **Make your changes** following the code style guidelines

3. **Write tests** for new functionality

4. **Update documentation** if needed

5. **Run tests and linters**:
   ```bash
   pytest
   pre-commit run --all-files
   ```

6. **Commit your changes**:
   ```bash
   git commit -m "feat: add new security rule for XYZ"
   ```
   Follow [Conventional Commits](https://www.conventionalcommits.org/) format:
   - `feat:` New feature
   - `fix:` Bug fix
   - `docs:` Documentation
   - `test:` Tests
   - `refactor:` Code refactoring
   - `chore:` Maintenance

7. **Push and create PR**:
   ```bash
   git push origin feature/my-feature
   ```
   Then create a Pull Request on GitHub.

### PR Checklist

- [ ] Tests pass locally
- [ ] Code follows style guidelines
- [ ] Documentation updated (if applicable)
- [ ] Changelog entry added (for significant changes)
- [ ] PR description explains the changes

## Reporting Issues

### Bug Reports

Include:
- Biceps-Check version
- Python version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Sample Bicep file (if applicable)

### Feature Requests

Include:
- Use case description
- Proposed solution
- Alternative solutions considered

### Security Vulnerabilities

Please report security vulnerabilities privately to the maintainers rather than opening a public issue.

## Questions?

Feel free to:
- Open a Discussion on GitHub
- Ask in PR/Issue comments
- Check existing documentation

Thank you for contributing to Biceps-Check!
