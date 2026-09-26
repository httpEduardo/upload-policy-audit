package audit

import (
	"testing"

	"github.com/httpEduardo/upload-policy-audit/internal/policy"
)

func ruleIDs(findings []Finding) map[string]Severity {
	out := map[string]Severity{}
	for _, f := range findings {
		out[f.RuleID] = f.Severity
	}
	return out
}

func TestSecurePolicyHasNoFindings(t *testing.T) {
	p := &policy.Policy{
		MaxMB:             10,
		AllowedExtensions: []string{"jpg", "png", "pdf"},
		AllowedMIME:       []string{"image/jpeg", "image/png", "application/pdf"},
		ScanEnabled:       true,
	}
	if got := Run(p, DefaultOptions()); len(got) != 0 {
		t.Fatalf("expected no findings, got %+v", got)
	}
}

func TestRules(t *testing.T) {
	tests := []struct {
		name   string
		policy policy.Policy
		want   map[string]Severity
	}{
		{
			name:   "empty policy",
			policy: policy.Policy{},
			want:   map[string]Severity{"UPA001": High, "UPA004": High, "UPA006": High, "UPA009": High},
		},
		{
			name: "server-side script is critical",
			policy: policy.Policy{
				MaxMB: 5, AllowedExtensions: []string{".PHP"}, AllowedMIME: []string{"image/png"}, ScanEnabled: true,
			},
			want: map[string]Severity{"UPA002": Critical},
		},
		{
			name: "svg is high because of stored XSS",
			policy: policy.Policy{
				MaxMB: 5, AllowedExtensions: []string{"svg"}, AllowedMIME: []string{"image/svg+xml"}, ScanEnabled: true,
			},
			want: map[string]Severity{"UPA002": High},
		},
		{
			name: "duplicates and oversized limit",
			policy: policy.Policy{
				MaxMB: 100, AllowedExtensions: []string{"png", "PNG"}, AllowedMIME: []string{"image/png"}, ScanEnabled: true,
			},
			want: map[string]Severity{"UPA003": Low, "UPA005": Medium},
		},
		{
			name: "wildcard MIME and extension without MIME",
			policy: policy.Policy{
				MaxMB: 5, AllowedExtensions: []string{"pdf"}, AllowedMIME: []string{"*/*"}, ScanEnabled: true,
			},
			want: map[string]Severity{"UPA007": High, "UPA008": Medium},
		},
		{
			name: "archives without scanning are critical",
			policy: policy.Policy{
				MaxMB: 5, AllowedExtensions: []string{"zip"}, AllowedMIME: []string{"application/zip"},
			},
			want: map[string]Severity{"UPA009": Critical},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ruleIDs(Run(&tt.policy, DefaultOptions()))
			if len(got) != len(tt.want) {
				t.Fatalf("got rules %v, want %v", got, tt.want)
			}
			for id, sev := range tt.want {
				if got[id] != sev {
					t.Errorf("rule %s: got severity %v, want %v", id, got[id], sev)
				}
			}
		})
	}
}

func TestFindingsAreSortedBySeverity(t *testing.T) {
	findings := Run(&policy.Policy{AllowedExtensions: []string{"exe", "png", "png"}}, DefaultOptions())
	for i := 1; i < len(findings); i++ {
		if findings[i].Severity > findings[i-1].Severity {
			t.Fatalf("findings not sorted: %v before %v", findings[i-1].Severity, findings[i].Severity)
		}
	}
}

func TestCustomSizeThreshold(t *testing.T) {
	p := &policy.Policy{MaxMB: 40, AllowedExtensions: []string{"png"}, AllowedMIME: []string{"image/png"}, ScanEnabled: true}
	if got := Run(p, Options{MaxRecommendedMB: 50}); len(got) != 0 {
		t.Fatalf("expected no findings with a 50 MB threshold, got %+v", got)
	}
}

func TestParseSeverity(t *testing.T) {
	if s, err := ParseSeverity(" HIGH "); err != nil || s != High {
		t.Fatalf("ParseSeverity(HIGH) = %v, %v", s, err)
	}
	if _, err := ParseSeverity("urgent"); err == nil {
		t.Fatal("expected an error for an unknown severity")
	}
}
