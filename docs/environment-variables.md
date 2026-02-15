# Environment Variables

Guardian CLI supports environment variable substitution in configuration files, allowing you to keep sensitive API keys out of your configuration files.

## Overview

Environment variables can be used in `guardian.yaml` using the syntax:

```yaml
api_key: "${VAR_NAME:-default_value}"
```

or simply:

```yaml
api_key: "${VAR_NAME}"
```

## Loading Environment Variables

Guardian loads environment variables from multiple sources in this order:

1. **System environment variables** (highest priority)
2. **`.env` file in current working directory**
3. **`.env` file adjacent to the config file** (e.g., `~/.guardian/.env`)

You can use `python-dotenv` syntax in `.env` files:

```bash
# .env file
GITHUB_TOKEN=ghp_xxxxxxxxxxxx
```

## OSINT API Keys

### GitHub Token

**Optional but recommended** - Increases GitHub API rate limit from 60/hour to 5000/hour.

```bash
# Get from: https://github.com/settings/tokens
# Required scopes: public_repo (read-only)
export GITHUB_TOKEN=ghp_xxxxxxxxxxxx
```

In `guardian.yaml`:

```yaml
osint:
  sources:
    github:
      token: "${GITHUB_TOKEN:-}"
```

## AI Provider API Keys

### Google Gemini

```bash
# Get from: https://makersuite.google.com/app/apikey
export GOOGLE_API_KEY=xxxxxxxxxxxx
```

### OpenRouter

```bash
# Get from: https://openrouter.ai/keys
export OPENROUTER_API_KEY=xxxxxxxxxxxx
```

### Hugging Face

```bash
# Get from: https://huggingface.co/settings/tokens
export HF_TOKEN=xxxxxxxxxxxx
```

## Environment Variable Syntax

### Basic Substitution

Replace with environment variable value, or empty string if not set:

```yaml
api_key: "${API_KEY}"
```

### Default Values

Replace with environment variable value, or use default if not set:

```yaml
api_key: "${API_KEY:-default_value}"
timeout: "${TIMEOUT:-30}"
enabled: "${FEATURE_ENABLED:-true}"
```

### Nested Values

Environment variables work in nested configuration:

```yaml
osint:
  sources:
    github:
      enabled: true
      token: "${GITHUB_TOKEN:-}"
      min_stars: "${GITHUB_MIN_STARS:-10}"
```

## Setup Guide

### Option 1: Using .env File (Recommended)

1. Copy the example file:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` and add your API keys:
   ```bash
   # OSINT API Keys
   GITHUB_TOKEN=ghp_xxxxxxxxxxxx
   ```

3. Run Guardian (it will automatically load `.env`):
   ```bash
   guardian scan example.com
   ```

### Option 2: Export Environment Variables

Export variables in your shell:

```bash
export GITHUB_TOKEN=ghp_xxxxxxxxxxxx

guardian scan example.com
```

### Option 3: Inline Environment Variables

Pass variables inline for a single command:

```bash
GITHUB_TOKEN=xxx guardian scan example.com
```

## Security Best Practices

### 1. Never Commit API Keys

Add `.env` to `.gitignore`:

```bash
echo ".env" >> .gitignore
```

### 2. Use .env.example as Template

The `.env.example` file documents required variables without exposing real keys:

```bash
# Safe to commit
cp .env.example .env.example.backup

# Never commit
.env
```

### 3. Restrict File Permissions

Protect your `.env` file:

```bash
chmod 600 .env
```

### 4. Use Different Keys for Different Environments

```bash
# Development
.env.dev

# Production
.env.prod

# Load specific environment
guardian scan --config config/dev.yaml example.com
```

### 5. Rotate API Keys Regularly

- Change API keys periodically
- Revoke compromised keys immediately
- Use fine-grained tokens with minimal scopes

## Verifying Configuration

Check that environment variables are loaded correctly:

```bash
# View loaded configuration (sanitized)
guardian config show

# Test OSINT sources
guardian osint test
```

## Troubleshooting

### API Key Not Loading

1. **Check environment variable is set:**
   ```bash
   echo $GITHUB_TOKEN
   ```

2. **Verify .env file exists and is readable:**
   ```bash
   ls -la .env
   cat .env
   ```

3. **Check for typos in variable names:**
   ```bash
   # Wrong
   api_key: "${GITHUBTOKEN}"

   # Correct
   api_key: "${GITHUB_TOKEN}"
   ```

4. **Verify syntax in guardian.yaml:**
   ```bash
   # Wrong - missing ${}
   api_key: "GITHUB_TOKEN"

   # Correct
   api_key: "${GITHUB_TOKEN}"
   ```

### Rate Limiting Issues

If you hit API rate limits:

1. **GitHub**: Add `GITHUB_TOKEN` to increase limit from 60/hour to 5000/hour

## Examples

### Complete .env Setup

```bash
# OSINT API Keys
GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef12345678

# AI Providers
GOOGLE_API_KEY=AIzaSy1234567890abcdef1234567890abcd
OPENROUTER_API_KEY=sk-or-v1-1234567890abcdef1234567890abcdef
HF_TOKEN=hf_1234567890abcdef1234567890abcdef

# Optional: Customization
GITHUB_MIN_STARS=5
EPSS_HIGH_RISK_THRESHOLD=0.8
```

### Testing Environment Variables

Create a test script:

```bash
#!/bin/bash
# test-env.sh

echo "Testing Guardian environment variables..."

if [ -z "$GITHUB_TOKEN" ]; then
    echo "❌ GITHUB_TOKEN not set"
else
    echo "✅ GITHUB_TOKEN set (${#GITHUB_TOKEN} characters)"
fi

# Run Guardian with loaded variables
guardian scan --help
```

### CI/CD Integration

For GitHub Actions:

```yaml
name: Security Scan

on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Run Guardian
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          guardian scan target.com
```

## Additional Resources

- [OSINT Sources Documentation](osint-sources.md)
- [Configuration Guide](../README.md#configuration)
- [API Key Setup Guide](OSINT_SETUP_GUIDE.md)
