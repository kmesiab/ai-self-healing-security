# AI Self-Healing Security

[![GitHub marketplace](https://img.shields.io/badge/marketplace-ai--self--healing--security-blue?logo=github)](https://github.com/marketplace/actions/ai-self-healing-security)
[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)

A language-agnostic security vulnerability scanner with extensible parser architecture. Automatically scans your code for security vulnerabilities, creates GitHub issues, and assigns them to GitHub Copilot for AI-powered self-healing remediation.

## Features

✨ **Multi-Language Support**: Automatically detects and scans Python, JavaScript/Node.js, Go, Ruby, and Java projects

🔍 **Comprehensive Scanning**: Integrates industry-standard security tools:

- **Python**: Safety, Bandit, Semgrep
- **JavaScript/Node.js**: npm audit, Retire.js, Snyk
- **Go**: gosec
- **Ruby**: bundler-audit, Brakeman

🤖 **AI-Powered Self-Healing**: Automatically assigns issues to GitHub Copilot-enabled users for intelligent, autonomous code remediation

⚙️ **Highly Configurable**:

- Severity thresholds (low, medium, high, critical)
- Build failure criteria
- Custom scan paths and exclusions
- Fallback assignee support

📊 **Smart Issue Management**:

- Automatic GitHub issue creation
- Deduplication to avoid redundant issues
- Auto-close fixed vulnerabilities
- Structured JSON output

## Quick Start

Add this workflow to your repository at `.github/workflows/security.yml`:

```yaml
name: Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * 0'  # Weekly scan

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run AI Self-Healing Security Scanner
        uses: kmesiab/ai-self-healing-security@v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          severity-threshold: 'medium'
          fail-on-severity: 'critical'
          copilot-assignee: 'your-github-username'
```

## Configuration

### Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|  
| `github-token` | GitHub token for creating issues | Yes | - |
| `languages` | Comma-separated languages to scan (auto-detection if omitted) | No | `auto` |
| `severity-threshold` | Minimum severity to report: low, medium, high, critical | No | `medium` |
| `fail-on-severity` | Fail build at this severity or higher | No | `critical` |
| `copilot-assignee` | GitHub username for Copilot-powered remediation | No | `` |
| `fallback-assignee` | Fallback assignee if Copilot user unavailable | No | `` |
| `auto-close-fixed` | Auto-close issues when vulnerabilities are fixed | No | `true` |
| `scan-path` | Path to scan | No | `.` |
| `exclude-paths` | Comma-separated paths to exclude | No | `` |
| `custom-parsers` | Path to custom parser configurations | No | `` |

### Outputs

| Output | Description |
|--------|-------------|
| `vulnerabilities-found` | Number of vulnerabilities detected |
| `issues-created` | Number of GitHub issues created |
| `scan-results` | JSON formatted scan results |
| `highest-severity` | Highest severity level found |

## Usage Examples

### Basic Scan with Auto-Detection

```yaml
- uses: kmesiab/ai-self-healing-security@v1
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

### Scan Specific Languages

```yaml
- uses: kmesiab/ai-self-healing-security@v1
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    languages: 'python,javascript,go'
    severity-threshold: 'high'
```

### Strict Mode with Copilot Integration

```yaml
- uses: kmesiab/ai-self-healing-security@v1
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    fail-on-severity: 'high'
    copilot-assignee: 'dev-team-lead'
    fallback-assignee: 'security-team'
```

### Scan Specific Directory

```yaml
- uses: kmesiab/ai-self-healing-security@v1
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    scan-path: './src'
    exclude-paths: './src/tests,./src/vendor'
```

## Supported Languages & Tools

### Python

- **Safety**: Checks for known security vulnerabilities in dependencies
- **Bandit**: Finds common security issues in Python code
- **Semgrep**: Pattern-based static analysis

### JavaScript/Node.js

- **npm audit**: Official npm security auditing tool
- **Retire.js**: Detects vulnerable JavaScript libraries
- **Snyk**: Finds and fixes vulnerabilities

### Go

- **gosec**: Inspects Go code for security problems

### Ruby

- **bundler-audit**: Checks for vulnerable gem versions
- **Brakeman**: Static analysis for Rails applications

### Java (Coming Soon)

- Dependency-Check
- SpotBugs with security plugins

## Architecture

The action follows a modular parser architecture:

1. **Language Detection**: Automatically identifies project languages
2. **Tool Execution**: Runs appropriate security scanners
3. **Result Parsing**: Unified parser for all tool outputs
4. **Issue Management**: Creates and manages GitHub issues
5. **AI Assignment**: Routes to Copilot for self-healing remediation

## Self-Healing with Copilot

When you specify a `copilot-assignee`, the action creates an organic, self-healing security loop:

1. Verifies the user exists and has repository access
2. Creates issues assigned to that user
3. Falls back to `fallback-assignee` if primary user is unavailable
4. Formats issues with structured data for AI processing
5. GitHub Copilot analyzes and suggests fixes
6. Auto-closes issues when vulnerabilities are resolved

This creates an almost organic, autonomous security remediation cycle.

## Security Considerations

- The action requires `issues: write` permission
- GitHub token is handled securely and never logged
- All scanner tools are installed from official sources
- Results are validated before creating issues

## Troubleshooting

### No vulnerabilities found

- Ensure your project has dependency files (requirements.txt, package.json, etc.)
- Check that the correct languages are being detected
- Lower the `severity-threshold` to see more results

### Permission denied errors

Ensure your workflow has proper permissions:

```yaml
permissions:
  contents: read
  issues: write
```

### Copilot user not found

- Verify the username is correct
- Ensure the user has repository access
- Consider adding a `fallback-assignee`

## Contributing

Contributions are welcome! Please see our [Wiki](../../wiki) for:

- Architecture documentation
- Adding new language support
- Custom parser development
- Testing guidelines

## License

MIT License - see [LICENSE](LICENSE) file for details

## Support

- 📖 [Documentation](../../wiki)
- 🐛 [Report Issues](../../issues)
- 💬 [Discussions](../../discussions)

## Related Projects

- [safetycli-self-healing-action](https://github.com/kmesiab/safetycli-self-healing-action) - Python-specific security scanner
- [GitHub Advanced Security](https://github.com/features/security) - GitHub's official security scanning

---

Made with ❤️ by [kmesiab](https://github.com/kmesiab)
