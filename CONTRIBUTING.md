# Contributing to Guardian

Thank you for your interest in contributing to Guardian! We welcome contributions from the security community.

## Code of Conduct

- Be respectful and professional
- Focus on constructive feedback
- Help us maintain Guardian as an ethical security tool
- Follow responsible disclosure for security issues

## How to Contribute

### Reporting Bugs

1. Check if the bug is already reported in [Issues](https://github.com/zakirkun/guardian-cli/issues)
2. If not, create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version, tool versions)
   - Relevant logs or screenshots

### Suggesting Features

1. Check [Discussions](https://github.com/zakirkun/guardian-cli/discussions) for similar ideas
2. Open a new discussion or issue describing:
   - The problem you're trying to solve
   - Your proposed solution
   - Why this would benefit Guardian users
   - Any implementation considerations

### Contributing Code

#### Setting Up Development Environment

```bash
# Fork and clone
git clone https://github.com/zakirkun/guardian-cli.git
cd guardian-cli

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or .\venv\Scripts\activate on Windows

# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

#### Development Workflow

1. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/issue-number
   ```

2. **Make Changes**
   - Follow existing code style
   - Add docstrings to functions/classes
   - Update documentation if needed
   - Add tests for new features

3. **Test Your Changes**
   ```bash
   # Run tests
   pytest tests/
   
   # Check code style
   black . --check
   flake8
   
   # Type checking
   mypy .
   ```

4. **Commit Changes**
   ```bash
   git add .
   git commit -m "feat: Add new feature"
   # or
   git commit -m "fix: Fix issue #123"
   ```

   **Commit Message Format:**
   - `feat:` New feature
   - `fix:` Bug fix
   - `docs:` Documentation changes
   - `test:` Test additions/changes
   - `refactor:` Code refactoring
   - `style:` Code style changes
   - `chore:` Maintenance tasks

5. **Push and Create PR**
   ```bash
   git push origin feature/your-feature-name
   ```
   Then create a Pull Request on GitHub.

## Contribution Areas

### 1. Tool Integrations

Add support for new pentesting tools:

- Create tool wrapper in `tools/`
- Follow `BaseTool` interface
- Add comprehensive parsing
- Include tests
- Update documentation

See [TOOLS_DEVELOPMENT_GUIDE.md](docs/TOOLS_DEVELOPMENT_GUIDE.md)

### 2. Workflows

Contribute workflow templates:

- Create YAML workflow in `workflows/`
- Include clear objectives for each step
- Test on safe targets
- Document use cases

See [WORKFLOW_GUIDE.md](docs/WORKFLOW_GUIDE.md)

### 3. AI Agents

Enhance or create new AI agents:

- Follow `BaseAgent` pattern
- Add clear prompts
- Include reasoning extraction
- Test with various scenarios

### 4. Documentation

Improve or add documentation:

- Fix typos and unclear sections
- Add usage examples
- Create tutorials
- Translate documentation

### 5. Testing

Expand test coverage:

- Unit tests for components
- Integration tests for workflows
- Mock external tool dependencies
- Edge case testing

## Code Style Guidelines

### Python Style

- Follow [PEP 8](https://pep8.org/)
- Use [Black](https://black.readthedocs.io/) for formatting
- Maximum line length: 100 characters
- Use type hints where possible

### Docstrings

```python
def function_name(param1: str, param2: int) -> Dict[str, Any]:
    """
    Brief description of function
    
    Args:
        param1: Description of param1
        param2: Description of param2
    
    Returns:
        Description of return value
    
    Raises:
        ExceptionType: When this exception occurs
    """
    pass
```

### Naming Conventions

- Classes: `PascalCase`
- Functions/methods: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Private methods: `_leading_underscore`

## Testing Requirements

### Unit Tests

All new code should include unit tests:

```python
import pytest
from tools.mytool import MyTool

def test_command_generation():
    tool = MyTool(config={})
    command = tool.get_command("example.com")
    assert "mytool" in command
    assert "example.com" in command

@pytest.mark.asyncio
async def test_execution():
    tool = MyTool(config={})
    result = await tool.execute("example.com")
    assert result["exit_code"] == 0
```

### Integration Tests

Mark integration tests appropriately:

```python
@pytest.mark.integration
@pytest.mark.skip(reason="Requires tool installation")
def test_real_execution():
    # Test with actual tool
    pass
```

## Security Considerations

### Responsible Development

- Never include real credentials or API keys
- Don't commit actual scan results
- Sanitize any example outputs
- Follow ethical testing principles

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities.

Instead:
1. Email security@example.com
2. Include detailed description
3. Provide steps to reproduce
4. Allow time for patch before disclosure

## Review Process

1. **Automated Checks**: CI/CD runs tests and linters
2. **Code Review**: Maintainers review your code
3. **Testing**: Verify functionality works
4. **Documentation**: Ensure docs are updated
5. **Merge**: PR merged into main branch

## Getting Help

- **Questions**: Use [Discussions](https://github.com/zakirkun/guardian-cli/discussions)
- **Bugs**: Open an [Issue](https://github.com/zakirkun/guardian-cli/issues)
- **Chat**: Join our Discord (link TBD)

## Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Credited in release notes
- Thanked in the community

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping make Guardian better! 🛡️
