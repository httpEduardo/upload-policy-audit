package policy

import (
	"strings"
	"testing"
)

func TestDecodeRejectsUnknownFields(t *testing.T) {
	_, err := Decode(strings.NewReader(`{"max_mbs": 10}`))
	if err == nil || !strings.Contains(err.Error(), "max_mbs") {
		t.Fatalf("expected an unknown field error, got %v", err)
	}
}

func TestDecodeRejectsEmptyInput(t *testing.T) {
	if _, err := Decode(strings.NewReader("   ")); err == nil {
		t.Fatal("expected an error for empty input")
	}
}

func TestNormalize(t *testing.T) {
	if got := NormalizeExtension(" ..PNG "); got != "png" {
		t.Errorf("NormalizeExtension = %q", got)
	}
	if got := NormalizeMIME("Text/Plain; charset=utf-8"); got != "text/plain" {
		t.Errorf("NormalizeMIME = %q", got)
	}
}
