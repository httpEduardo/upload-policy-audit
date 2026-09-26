package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePolicy(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunExitCodes(t *testing.T) {
	secure := writePolicy(t, `{"max_mb":10,"allowed_extensions":["png"],"allowed_mime":["image/png"],"scan_enabled":true}`)
	risky := writePolicy(t, `{"max_mb":10,"allowed_extensions":["php"],"allowed_mime":["image/png"],"scan_enabled":true}`)

	tests := []struct {
		name string
		args []string
		want int
	}{
		{"secure policy", []string{"-input", secure}, exitOK},
		{"risky policy", []string{"-input", risky}, exitFindings},
		{"risky at critical threshold", []string{"-input", risky, "-fail-on", "critical"}, exitFindings},
		{"missing file", []string{"-input", "does-not-exist.json"}, exitUsage},
		{"bad format", []string{"-input", secure, "-format", "xml"}, exitUsage},
		{"bad severity", []string{"-input", secure, "-fail-on", "urgent"}, exitUsage},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if got := run(tt.args, &out, &errOut); got != tt.want {
				t.Fatalf("exit code = %d, want %d (stderr: %s)", got, tt.want, errOut.String())
			}
		})
	}
}

func TestRunJSONOutput(t *testing.T) {
	path := writePolicy(t, `{"max_mb":10,"allowed_extensions":["png"],"allowed_mime":["image/png"],"scan_enabled":false}`)

	var out, errOut bytes.Buffer
	run([]string{"-input", path, "-format", "json"}, &out, &errOut)

	var got struct {
		Findings []struct {
			RuleID   string `json:"rule_id"`
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, out.String())
	}
	if len(got.Findings) != 1 || got.Findings[0].RuleID != "UPA009" || got.Findings[0].Severity != "high" {
		t.Fatalf("unexpected findings: %+v", got.Findings)
	}
}

func TestRunTextOutput(t *testing.T) {
	path := writePolicy(t, `{"max_mb":10,"allowed_extensions":["png"],"allowed_mime":["image/png"],"scan_enabled":true}`)

	var out, errOut bytes.Buffer
	run([]string{"-input", path}, &out, &errOut)
	if !strings.Contains(out.String(), "no findings") {
		t.Fatalf("unexpected output: %s", out.String())
	}
}
