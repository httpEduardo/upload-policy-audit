// Command upload-policy-audit reviews a file upload policy and reports
// settings that could let attackers upload malicious content.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/httpEduardo/upload-policy-audit/internal/audit"
	"github.com/httpEduardo/upload-policy-audit/internal/policy"
	"github.com/httpEduardo/upload-policy-audit/internal/report"
)

// Exit codes are stable so the tool can gate CI pipelines.
const (
	exitOK       = 0
	exitFindings = 1
	exitUsage    = 2
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("upload-policy-audit", flag.ContinueOnError)
	fs.SetOutput(stderr)

	input := fs.String("input", "policy.json", "path to the upload policy JSON file")
	format := fs.String("format", "text", "output format: text or json")
	failOn := fs.String("fail-on", "high", "exit with code 1 when a finding reaches this severity (low, medium, high, critical)")
	maxMB := fs.Int("max-mb", audit.DefaultOptions().MaxRecommendedMB, "largest upload size, in MB, considered acceptable")
	showVersion := fs.Bool("version", false, "print the version and exit")

	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: upload-policy-audit [flags]\n\nFlags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return exitOK
		}
		return exitUsage
	}

	if *showVersion {
		fmt.Fprintln(stdout, version)
		return exitOK
	}

	outFormat, err := report.ParseFormat(*format)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitUsage
	}
	threshold, err := audit.ParseSeverity(*failOn)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitUsage
	}

	p, err := policy.Load(*input)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitUsage
	}

	findings := audit.Run(p, audit.Options{MaxRecommendedMB: *maxMB})
	if err := report.Write(stdout, outFormat, *input, findings); err != nil {
		fmt.Fprintln(stderr, "error: writing report:", err)
		return exitUsage
	}

	if audit.Worst(findings) >= threshold {
		return exitFindings
	}
	return exitOK
}
