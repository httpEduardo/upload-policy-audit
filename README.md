# Upload Policy Audit

![Go](https://img.shields.io/badge/Go-1.21%2B-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

**Review file-upload settings before they reach production.**

Upload Policy Audit checks a JSON policy for risky file types, missing size and MIME restrictions, and disabled malware scanning. It reports the settings that need a closer look, with a suggested next step.

## Quick start

```bash
go install github.com/httpEduardo/upload-policy-audit/cmd/upload-policy-audit@latest
upload-policy-audit -input policy.json
```

Try the included example from a clone:

```bash
git clone https://github.com/httpEduardo/upload-policy-audit.git
cd upload-policy-audit
go run ./cmd/upload-policy-audit -input examples/policy.json
```

## Policy example

```json
{
  "max_mb": 10,
  "allowed_extensions": ["jpg", "png", "pdf"],
  "allowed_mime": ["image/jpeg", "image/png", "application/pdf"],
  "scan_enabled": true
}
```

Use `-format json` for structured output or `-fail-on high` to use the audit in CI.

## Scope

This tool reviews policy settings; it does not verify that the upload handler enforces them or scans the actual file contents. Treat a clean report as a useful baseline, alongside a review of the application code.

## License

[MIT](LICENSE)
