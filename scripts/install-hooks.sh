#!/bin/bash
#
# Install git hooks for bskyoauth
#
# This script installs pre-commit hooks that run security checks and tests
# before allowing commits.
#

set -e

echo "Installing git hooks for bskyoauth..."
echo ""

# Check if we're in a git repository
if [ ! -d .git ]; then
    echo "❌ Error: Not in a git repository"
    echo "   Please run this script from the repository root"
    exit 1
fi

# Install pre-commit hook
if [ -f .git/hooks/pre-commit ]; then
    echo "⚠️  Pre-commit hook already exists"
    read -p "   Overwrite? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "❌ Cancelled"
        exit 1
    fi
fi

cp scripts/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

echo "✅ Pre-commit hook installed!"
echo ""
echo "The following checks will run before each commit:"
echo "  - gofmt (code formatting check)"
echo "  - golangci-lint (code quality and style)"
echo "  - govulncheck (vulnerability scanning)"
echo "  - go test -race (tests with race detection)"
echo "  - go mod verify (dependency verification)"
echo ""
echo "Optional tools (will auto-install if needed):"
echo "  - golangci-lint: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"
echo "  - govulncheck: go install golang.org/x/vuln/cmd/govulncheck@latest"
echo ""
echo "To bypass checks: git commit --no-verify"
echo "To uninstall: rm .git/hooks/pre-commit"
