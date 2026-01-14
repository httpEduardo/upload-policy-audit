# Upload Policy Audit

Upload Policy Audit reviews upload constraints and flags risky file types or size limits.

## Quick start

```bash
go run main.go --input policy.json
```

## Output

Lists high-risk extensions, missing MIME validation, and oversized limits.
