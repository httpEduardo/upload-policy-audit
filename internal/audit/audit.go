// Package audit evaluates an upload policy against a set of security rules.
package audit

import (
	"fmt"
	"sort"
	"strings"

	"github.com/httpEduardo/upload-policy-audit/internal/policy"
)

// Severity ranks how serious a finding is.
type Severity int

const (
	Low Severity = iota + 1
	Medium
	High
	Critical
)

var severityNames = map[Severity]string{
	Low:      "low",
	Medium:   "medium",
	High:     "high",
	Critical: "critical",
}

func (s Severity) String() string {
	if name, ok := severityNames[s]; ok {
		return name
	}
	return "unknown"
}

// MarshalText lets severities appear as strings in JSON output.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// ParseSeverity converts a name such as "high" into a Severity.
func ParseSeverity(name string) (Severity, error) {
	for sev, n := range severityNames {
		if strings.EqualFold(n, strings.TrimSpace(name)) {
			return sev, nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q (want low, medium, high or critical)", name)
}

// Finding is a single issue detected in a policy.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	Severity    Severity `json:"severity"`
	Message     string   `json:"message"`
	Remediation string   `json:"remediation"`
}

// Options tunes the audit thresholds.
type Options struct {
	// MaxRecommendedMB is the size above which a limit is flagged as too permissive.
	MaxRecommendedMB int
}

// DefaultOptions returns the thresholds used when none are provided.
func DefaultOptions() Options {
	return Options{MaxRecommendedMB: 25}
}

// Extensions that can execute code on the server or in the browser.
var dangerousExtensions = map[string]Severity{
	// Server-side scripts and deployable archives.
	"php": Critical, "php3": Critical, "php4": Critical, "php5": Critical, "phtml": Critical, "phar": Critical,
	"jsp": Critical, "jspx": Critical, "war": Critical, "asp": Critical, "aspx": Critical, "ashx": Critical,
	"cgi": Critical, "pl": Critical, "py": Critical, "rb": Critical,
	// Native executables and OS scripts.
	"exe": Critical, "dll": Critical, "msi": Critical, "com": Critical, "scr": Critical,
	"bat": Critical, "cmd": Critical, "ps1": Critical, "vbs": Critical, "sh": Critical, "jar": Critical,
	// Content that runs in the victim's browser (stored XSS).
	"js": High, "html": High, "htm": High, "xhtml": High, "svg": High, "swf": High,
}

// Extensions that hide other files and need scanning to be inspected.
var archiveExtensions = map[string]bool{
	"zip": true, "rar": true, "7z": true, "tar": true, "gz": true, "tgz": true, "bz2": true,
}

// Expected MIME types for common extensions, used to spot gaps between
// the extension allowlist and the MIME allowlist.
var expectedMIME = map[string][]string{
	"jpg":  {"image/jpeg"},
	"jpeg": {"image/jpeg"},
	"png":  {"image/png"},
	"gif":  {"image/gif"},
	"webp": {"image/webp"},
	"pdf":  {"application/pdf"},
	"txt":  {"text/plain"},
	"csv":  {"text/csv"},
	"zip":  {"application/zip", "application/x-zip-compressed"},
	"docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
	"xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
}

// MIME entries that accept almost anything and defeat content validation.
var permissiveMIME = map[string]bool{
	"*/*":                      true,
	"*":                        true,
	"application/octet-stream": true,
	"application/*":            true,
}

// Run audits the policy and returns findings ordered from most to least severe.
func Run(p *policy.Policy, opts Options) []Finding {
	if opts.MaxRecommendedMB <= 0 {
		opts.MaxRecommendedMB = DefaultOptions().MaxRecommendedMB
	}

	exts := normalizedSet(p.AllowedExtensions, policy.NormalizeExtension)
	mimes := normalizedSet(p.AllowedMIME, policy.NormalizeMIME)

	var findings []Finding
	findings = append(findings, checkExtensions(p, exts)...)
	findings = append(findings, checkSize(p, opts)...)
	findings = append(findings, checkMIME(exts, mimes)...)
	findings = append(findings, checkScanning(p, exts)...)

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity > findings[j].Severity
		}
		return findings[i].RuleID < findings[j].RuleID
	})
	return findings
}

func checkExtensions(p *policy.Policy, exts map[string]bool) []Finding {
	if len(exts) == 0 {
		return []Finding{{
			RuleID:      "UPA001",
			Severity:    High,
			Message:     "no extension allowlist is defined, so any file type is accepted",
			Remediation: "List only the extensions your feature actually needs.",
		}}
	}

	var out []Finding
	for _, ext := range sortedKeys(exts) {
		if sev, ok := dangerousExtensions[ext]; ok {
			out = append(out, Finding{
				RuleID:      "UPA002",
				Severity:    sev,
				Message:     fmt.Sprintf("dangerous extension allowed: .%s", ext),
				Remediation: fmt.Sprintf("Remove .%s from the allowlist, or serve such files from an isolated domain with Content-Disposition: attachment.", ext),
			})
		}
	}

	if len(exts) < len(p.AllowedExtensions) {
		out = append(out, Finding{
			RuleID:      "UPA003",
			Severity:    Low,
			Message:     "extension allowlist contains duplicates or mixed-case variants",
			Remediation: "Keep one lowercase entry per extension so the policy is easy to review.",
		})
	}
	return out
}

func checkSize(p *policy.Policy, opts Options) []Finding {
	switch {
	case p.MaxMB <= 0:
		return []Finding{{
			RuleID:      "UPA004",
			Severity:    High,
			Message:     "no upload size limit is configured",
			Remediation: "Set max_mb to protect storage and prevent denial-of-service through large uploads.",
		}}
	case p.MaxMB > opts.MaxRecommendedMB:
		return []Finding{{
			RuleID:      "UPA005",
			Severity:    Medium,
			Message:     fmt.Sprintf("upload size limit is %d MB, above the recommended %d MB", p.MaxMB, opts.MaxRecommendedMB),
			Remediation: "Lower max_mb, or use chunked/resumable uploads for large files.",
		}}
	}
	return nil
}

func checkMIME(exts, mimes map[string]bool) []Finding {
	if len(mimes) == 0 {
		return []Finding{{
			RuleID:      "UPA006",
			Severity:    High,
			Message:     "no MIME allowlist is defined, so file content is never validated",
			Remediation: "Validate the detected content type (magic bytes), not just the extension.",
		}}
	}

	var out []Finding
	for _, m := range sortedKeys(mimes) {
		if permissiveMIME[m] {
			out = append(out, Finding{
				RuleID:      "UPA007",
				Severity:    High,
				Message:     fmt.Sprintf("overly permissive MIME type allowed: %s", m),
				Remediation: "Replace wildcard or generic binary types with the specific types you expect.",
			})
		}
	}

	for _, ext := range sortedKeys(exts) {
		want, known := expectedMIME[ext]
		if !known || anyIn(want, mimes) {
			continue
		}
		out = append(out, Finding{
			RuleID:      "UPA008",
			Severity:    Medium,
			Message:     fmt.Sprintf(".%s is allowed but no matching MIME type is (expected %s)", ext, strings.Join(want, " or ")),
			Remediation: "Keep the extension and MIME allowlists in sync, or uploads will be rejected or validated inconsistently.",
		})
	}
	return out
}

func checkScanning(p *policy.Policy, exts map[string]bool) []Finding {
	if p.ScanEnabled {
		return nil
	}

	f := Finding{
		RuleID:      "UPA009",
		Severity:    High,
		Message:     "malware scanning is disabled",
		Remediation: "Scan uploads (for example with ClamAV or a cloud scanning service) before they are stored or served.",
	}

	var archives []string
	for _, ext := range sortedKeys(exts) {
		if archiveExtensions[ext] {
			archives = append(archives, "."+ext)
		}
	}
	if len(archives) > 0 {
		f.Severity = Critical
		f.Message = fmt.Sprintf("malware scanning is disabled while archives are accepted (%s)", strings.Join(archives, ", "))
	}
	return []Finding{f}
}

// Worst returns the highest severity among findings, or 0 if there are none.
func Worst(findings []Finding) Severity {
	var worst Severity
	for _, f := range findings {
		if f.Severity > worst {
			worst = f.Severity
		}
	}
	return worst
}

func normalizedSet(values []string, normalize func(string) string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, v := range values {
		if n := normalize(v); n != "" {
			set[n] = true
		}
	}
	return set
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func anyIn(values []string, set map[string]bool) bool {
	for _, v := range values {
		if set[v] {
			return true
		}
	}
	return false
}
