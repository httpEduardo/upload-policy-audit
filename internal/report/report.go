// Package report renders audit findings for humans and machines.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/httpEduardo/upload-policy-audit/internal/audit"
)

// Format selects the output encoding.
type Format string

const (
	Text Format = "text"
	JSON Format = "json"
)

// ParseFormat validates a format name.
func ParseFormat(name string) (Format, error) {
	switch f := Format(strings.ToLower(strings.TrimSpace(name))); f {
	case Text, JSON:
		return f, nil
	}
	return "", fmt.Errorf("unknown format %q (want text or json)", name)
}

type jsonReport struct {
	Policy   string          `json:"policy"`
	Summary  map[string]int  `json:"summary"`
	Findings []audit.Finding `json:"findings"`
}

// Write renders findings for the policy at source in the given format.
func Write(w io.Writer, format Format, source string, findings []audit.Finding) error {
	if format == JSON {
		return writeJSON(w, source, findings)
	}
	return writeText(w, source, findings)
}

func writeJSON(w io.Writer, source string, findings []audit.Finding) error {
	if findings == nil {
		findings = []audit.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jsonReport{Policy: source, Summary: summarize(findings), Findings: findings})
}

func writeText(w io.Writer, source string, findings []audit.Finding) error {
	if len(findings) == 0 {
		_, err := fmt.Fprintf(w, "%s: no findings\n", source)
		return err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s: %d finding(s)\n\n", source, len(findings))
	for _, f := range findings {
		fmt.Fprintf(&b, "  [%s] %-8s %s\n", f.RuleID, strings.ToUpper(f.Severity.String()), f.Message)
		fmt.Fprintf(&b, "  %s   -> %s\n\n", strings.Repeat(" ", len(f.RuleID)), f.Remediation)
	}

	counts := summarize(findings)
	var parts []string
	for _, sev := range []audit.Severity{audit.Critical, audit.High, audit.Medium, audit.Low} {
		if n := counts[sev.String()]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	fmt.Fprintf(&b, "Summary: %s\n", strings.Join(parts, ", "))

	_, err := io.WriteString(w, b.String())
	return err
}

func summarize(findings []audit.Finding) map[string]int {
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity.String()]++
	}
	return counts
}
