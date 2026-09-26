# upload-policy-audit

A small command-line tool that reviews a file upload policy and points out the settings most likely to get you in trouble: executable extensions on the allowlist, missing content validation, no size limit, and uploads that are never scanned.

File uploads are one of the easiest ways into a web application. A single `.php` or `.svg` that slips through an allowlist can turn into remote code execution or stored XSS. Most of these mistakes live in configuration rather than code, so they are cheap to catch early — if something is actually looking. This tool does that looking, and it's built to run in CI so a risky change to the policy fails the build instead of reaching production.

## What it checks

| Rule | Severity | What it flags |
|------|----------|---------------|
| `UPA001` | High | No extension allowlist, so any file type is accepted |
| `UPA002` | Critical / High | Extensions that execute on the server (`.php`, `.jsp`, `.exe`, `.sh`, …) or in the browser (`.html`, `.js`, `.svg`) |
| `UPA003` | Low | Duplicate or mixed-case entries in the extension allowlist |
| `UPA004` | High | No upload size limit configured |
| `UPA005` | Medium | Size limit above the recommended threshold (25 MB by default) |
| `UPA006` | High | No MIME allowlist, so file content is never validated |
| `UPA007` | High | Catch-all MIME types such as `*/*` or `application/octet-stream` |
| `UPA008` | Medium | An allowed extension with no matching MIME type (e.g. `.zip` without `application/zip`) |
| `UPA009` | High / Critical | Malware scanning disabled — critical when archives are accepted, since they can hide anything |

Extensions and MIME types are normalized before comparison, so `.PNG`, `png` and `image/PNG; charset=binary` are all treated consistently.

## Installation

Requires Go 1.21 or newer.

```bash
go install github.com/httpEduardo/upload-policy-audit/cmd/upload-policy-audit@latest
```

Or build from source:

```bash
git clone https://github.com/httpEduardo/upload-policy-audit.git
cd upload-policy-audit
make build        # binary ends up in ./bin
```

## Usage

```bash
upload-policy-audit -input examples/policy.json
```

```text
examples/policy.json: 4 finding(s)

  [UPA002] CRITICAL dangerous extension allowed: .exe
           -> Remove .exe from the allowlist, or serve such files from an isolated domain with Content-Disposition: attachment.

  [UPA009] CRITICAL malware scanning is disabled while archives are accepted (.zip)
           -> Scan uploads (for example with ClamAV or a cloud scanning service) before they are stored or served.

  [UPA005] MEDIUM   upload size limit is 50 MB, above the recommended 25 MB
           -> Lower max_mb, or use chunked/resumable uploads for large files.

  [UPA008] MEDIUM   .zip is allowed but no matching MIME type is (expected application/zip or application/x-zip-compressed)
           -> Keep the extension and MIME allowlists in sync, or uploads will be rejected or validated inconsistently.

Summary: 2 critical, 2 medium
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-input` | `policy.json` | Path to the policy file |
| `-format` | `text` | `text` for people, `json` for scripts and dashboards |
| `-fail-on` | `high` | Lowest severity that makes the command exit with code `1` |
| `-max-mb` | `25` | Largest upload size, in MB, you consider acceptable |
| `-version` | | Print the version and exit |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No findings at or above `-fail-on` |
| `1` | At least one finding at or above `-fail-on` |
| `2` | Invalid flags, unreadable file or malformed policy |

## Policy format

```json
{
  "max_mb": 10,
  "allowed_extensions": ["jpg", "jpeg", "png", "pdf"],
  "allowed_mime": ["image/jpeg", "image/png", "application/pdf"],
  "scan_enabled": true
}
```

| Field | Type | Notes |
|-------|------|-------|
| `max_mb` | integer | Maximum upload size in megabytes. `0` or missing means no limit. |
| `allowed_extensions` | string[] | Extension allowlist, with or without the leading dot. |
| `allowed_mime` | string[] | Content types accepted after inspecting the file. |
| `scan_enabled` | boolean | Whether uploads are scanned for malware. |

Unknown fields are rejected on purpose — a typo like `"max_mbs"` would otherwise silently switch a check off.

`examples/` has a deliberately weak policy (`policy.json`) and a clean one (`secure-policy.json`) to compare against.

## Using it in CI

```yaml
- name: Audit upload policy
  run: go run github.com/httpEduardo/upload-policy-audit/cmd/upload-policy-audit@latest -input config/upload-policy.json -fail-on high
```

Need the results somewhere else? `-format json` prints a stable structure with a per-severity summary:

```bash
upload-policy-audit -input policy.json -format json | jq '.summary'
```

## Project layout

```
cmd/upload-policy-audit/   CLI entry point and flag handling
internal/policy/           Loading, validating and normalizing policies
internal/audit/            The rules and severity model
internal/report/           Text and JSON output
examples/                  Sample policies
```

## Development

```bash
make test    # go test -race -cover ./...
make lint    # gofmt + go vet
make run     # audit the sample policy
```

Adding a rule usually means one function in `internal/audit/audit.go` plus a case in the table test next to it. Keep rule IDs stable once published, since people may filter on them.

## Limitations

This tool reviews the *policy*, not the code that enforces it. A perfect policy doesn't help if the upload handler trusts the client-supplied `Content-Type` or never calls the scanner. Treat a clean report as a baseline, not a guarantee, and pair it with a code review of the upload path.

## License

[MIT](LICENSE)
