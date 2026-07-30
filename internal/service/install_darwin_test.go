//go:build darwin

package service

import "testing"

func TestBootstrapInProgressRecognisesTheBootoutRace(t *testing.T) {
	cases := []struct {
		out  string
		want bool
	}{
		{"Bootstrap failed: 37: Operation already in progress", true},
		{"Bootstrap failed: 5: Input/output error", false},
		{"", false},
		{"something 37: buried in text", true},
	}
	for _, tc := range cases {
		if got := bootstrapInProgress(tc.out); got != tc.want {
			t.Errorf("bootstrapInProgress(%q) = %v, want %v", tc.out, got, tc.want)
		}
	}
}
