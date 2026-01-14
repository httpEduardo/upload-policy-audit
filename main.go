package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "os"
    "strings"
)

type Policy struct {
    MaxMB            int      `json:"max_mb"`
    AllowedExt       []string `json:"allowed_extensions"`
    AllowedMIME      []string `json:"allowed_mime"`
    ScanEnabled      bool     `json:"scan_enabled"`
}

var riskyExt = []string{"exe", "js", "php", "jsp", "war", "bat", "cmd"}

func contains(list []string, value string) bool {
    for _, item := range list {
        if strings.EqualFold(item, value) {
            return true
        }
    }
    return false
}

func main() {
    input := flag.String("input", "policy.json", "Upload policy JSON")
    flag.Parse()

    raw, err := os.ReadFile(*input)
    if err != nil {
        fmt.Println("Failed to read policy:", err)
        os.Exit(1)
    }

    var policy Policy
    if err := json.Unmarshal(raw, &policy); err != nil {
        fmt.Println("Invalid JSON:", err)
        os.Exit(1)
    }

    findings := []string{}

    for _, ext := range riskyExt {
        if contains(policy.AllowedExt, ext) {
            findings = append(findings, fmt.Sprintf("risky extension allowed: %s", ext))
        }
    }

    if policy.MaxMB > 25 {
        findings = append(findings, "max upload size exceeds 25MB")
    }

    if len(policy.AllowedMIME) == 0 {
        findings = append(findings, "missing MIME allowlist")
    }

    if !policy.ScanEnabled {
        findings = append(findings, "malware scanning disabled")
    }

    if len(findings) == 0 {
        fmt.Println("No findings.")
        return
    }

    fmt.Println("Findings:")
    for _, finding := range findings {
        fmt.Printf("- %s\n", finding)
    }
}
