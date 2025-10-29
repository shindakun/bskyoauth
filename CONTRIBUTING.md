# Contributing to bskyoauth

Thank you for your interest in contributing to bskyoauth! This document provides guidelines for contributing to the project.

## Development Setup

1. **Fork and clone the repository:**
   ```bash
   git clone https://github.com/yourusername/bskyoauth.git
   cd bskyoauth
   ```

2. **Install Go 1.25.3 or later:**
   ```bash
   go version
   ```

3. **Install development dependencies:**
   ```bash
   go mod download
   go install golang.org/x/vuln/cmd/govulncheck@latest
   ```

4. **Install pre-commit hooks (recommended):**
   ```bash
   ./scripts/install-hooks.sh
   ```

   This installs git hooks that automatically run before each commit:
   - `govulncheck` - Vulnerability scanning
   - `go test -race` - Tests with race detection
   - `go mod verify` - Dependency verification

   To bypass: `git commit --no-verify`

## Making Changes

1. **Create a new branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes:**
   - Write clear, concise commit messages
   - Follow existing code style and conventions
   - Add tests for new functionality
   - Update documentation as needed

3. **Run tests:**
   ```bash
   go test -v -race ./...
   ```

4. **Run security checks:**
   ```bash
   govulncheck ./...
   ```

5. **Verify dependencies:**
   ```bash
   go mod verify
   go mod tidy
   ```

## Testing

- **Run all tests:**
  ```bash
  go test -v ./...
  ```

- **Run with race detection:**
  ```bash
  go test -race ./...
  ```

- **Run with coverage:**
  ```bash
  go test -coverprofile=coverage.out ./...
  go tool cover -html=coverage.out
  ```

- **Run specific test:**
  ```bash
  go test -v -run TestFunctionName
  ```

## Code Style

- Follow standard Go conventions and idioms
- Use `gofmt` to format code (happens automatically on save in most editors)
- Run `go vet` to catch common mistakes
- Write clear comments for exported functions and types
- Keep functions focused and concise

## Security

- Never commit secrets, API keys, or credentials
- Run `govulncheck` before committing
- Update dependencies regularly
- Report security vulnerabilities privately (see SECURITY.md if available)

## Pull Request Process

1. **Update documentation:**
   - Update README.md if adding features
   - Update CHANGELOG.md with your changes
   - Add comments to exported functions

2. **Ensure all checks pass:**
   - All tests pass
   - No vulnerabilities detected
   - Dependencies verified
   - Code formatted with `gofmt`

3. **Submit pull request:**
   - Provide a clear description of changes
   - Reference related issues
   - Include examples if adding new features

4. **Respond to feedback:**
   - Address review comments promptly
   - Update PR based on feedback
   - Keep commits clean and organized

## Commit Message Guidelines

Follow conventional commit format:

```
type(scope): brief description

Detailed explanation if needed.

- Bullet points for multiple changes
- Another change

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Your Name <your.email@example.com>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Test additions or changes
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `chore`: Maintenance tasks
- `deps`: Dependency updates

## Questions?

Feel free to open an issue for:
- Bug reports
- Feature requests
- Questions about usage
- General discussion

Thank you for contributing! 🎉
