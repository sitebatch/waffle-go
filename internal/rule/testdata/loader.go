package testdata

import (
	"os"
	"testing"
)

func MustReadRule(t *testing.T, filename string) []byte {
	t.Helper()

	rule, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("failed to read rule file: %v", err)
	}

	return rule
}
