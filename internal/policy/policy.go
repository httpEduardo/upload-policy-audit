// Package policy loads and normalizes file upload policies.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Policy describes the upload rules enforced by an application.
type Policy struct {
	// MaxMB is the maximum accepted upload size in megabytes.
	// Zero or a negative value means "no limit configured".
	MaxMB int `json:"max_mb"`

	// AllowedExtensions is the allowlist of file extensions, without the dot.
	AllowedExtensions []string `json:"allowed_extensions"`

	// AllowedMIME is the allowlist of MIME types checked against the content.
	AllowedMIME []string `json:"allowed_mime"`

	// ScanEnabled reports whether uploads go through malware scanning.
	ScanEnabled bool `json:"scan_enabled"`
}

// Load reads a policy from a JSON file.
func Load(path string) (*Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open policy: %w", err)
	}
	defer f.Close()
	return Decode(f)
}

// Decode parses a policy from JSON. Unknown fields are rejected so that
// typos such as "max_mbs" do not silently disable a check.
func Decode(r io.Reader) (*Policy, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, errors.New("policy is empty")
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()

	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	return &p, nil
}

// NormalizeExtension lowercases an extension and strips surrounding
// whitespace and any leading dots, so ".PNG" and "png" compare equal.
func NormalizeExtension(ext string) string {
	return strings.TrimLeft(strings.ToLower(strings.TrimSpace(ext)), ".")
}

// NormalizeMIME lowercases a MIME type and drops parameters such as
// "; charset=utf-8".
func NormalizeMIME(mime string) string {
	mime = strings.ToLower(strings.TrimSpace(mime))
	if i := strings.IndexByte(mime, ';'); i >= 0 {
		mime = strings.TrimSpace(mime[:i])
	}
	return mime
}
