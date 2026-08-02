package cmd

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Every scoring knob must be settable from the command line. The standing
// complaint this feature answers is settings that exist but are neither
// visible nor reachable — a field that only the API can write is exactly that,
// and it appears silently: the console gets a control, the CLI just never
// mentions it.
//
// Reflecting over the wire type means adding a knob later fails here rather
// than shipping half-wired.
func TestEveryScoringKnobHasAFlag(t *testing.T) {
	flags := groupsScoringCmd.Flags()

	// json tag -> flag name. Named per knob so a mismatch reads as one line.
	want := map[string]string{
		"min_samples":           "min-samples",
		"weight_reliability":    "weight-reliability",
		"weight_latency":        "weight-latency",
		"weight_throughput":     "weight-throughput",
		"reward_per_success":    "reward",
		"penalty_per_failure":   "penalty",
		"max_streak":            "max-streak",
		"latency_good_ms":       "latency-good",
		"latency_bad_ms":        "latency-bad",
		"throughput_good_kbps":  "throughput-good",
		"tie_margin_points":     "tie-margin",
		"breaker_failures":      "breaker-failures",
		"breaker_delay_seconds": "breaker-delay",
		"breaker_successes":     "breaker-successes",
		"stale_hours":           "stale-hours",
		"blackhole_streak":         "blackhole-streak",
		"stream_stall_sec":         "stream-stall",
		"stream_stall_min_upload":  "stream-stall-min-upload",
		"stream_stall_min_age_sec": "stream-stall-min-age",
		"disabled":                 "disabled",
	}

	rt := reflect.TypeOf(apitypes.ProxyScoring{})
	for i := 0; i < rt.NumField(); i++ {
		tag := strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]
		if tag == "" || tag == "-" {
			continue
		}
		name, ok := want[tag]
		if !ok {
			t.Fatalf("new scoring knob %q has no CLI flag mapping — a setting reachable only from the API is invisible to scripts", tag)
		}
		if flags.Lookup(name) == nil {
			t.Fatalf("scoring knob %q maps to flag --%s, which is not registered", tag, name)
		}
		delete(want, tag)
	}
	if len(want) != 0 {
		t.Fatalf("flags mapped to fields that no longer exist: %v", want)
	}
}

// scoringFlags drives the "did the user change anything" check; if it drifts
// from the registered flags, a patch silently becomes a no-op read.
func TestScoringFlagListMatchesRegisteredFlags(t *testing.T) {
	for _, name := range scoringFlags {
		if groupsScoringCmd.Flags().Lookup(name) == nil {
			t.Fatalf("scoringFlags names --%s, which is not registered", name)
		}
	}
	n := 0
	groupsScoringCmd.Flags().VisitAll(func(*pflag.Flag) { n++ })
	if n != len(scoringFlags) {
		t.Fatalf("registered %d flags but scoringFlags lists %d — a flag the change-check ignores never takes effect", n, len(scoringFlags))
	}
}

// A warming node must not print a bare 100: read as "measured and excellent"
// it is the opposite of what it means.
func TestScoreStateNamesWarmupAndDemotion(t *testing.T) {
	if got := scoreState(apitypes.ProxyScore{Preferred: true, Warming: true}); got != "warming" {
		t.Fatalf("warming state = %q", got)
	}
	got := scoreState(apitypes.ProxyScore{Breaker: "open", BreakerRemaining: 12})
	if !strings.Contains(got, "demoted") || !strings.Contains(got, "12s") {
		t.Fatalf("demoted state must say so and show the remaining delay, got %q", got)
	}
	if got := streakText(apitypes.ProxyScore{FailStreak: 3}); got != "3 fail" {
		t.Fatalf("streak = %q", got)
	}
}

// The zero Config must serialise to an empty object: "unset" has to stay
// distinguishable from "explicitly zero", or a patch of one knob would write
// zeros over every other one on the gateway.
func TestUnsetScoringKnobsAreOmitted(t *testing.T) {
	b, err := json.Marshal(apitypes.ProxyScoring{})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "{}" {
		t.Fatalf("zero ProxyScoring = %s, want {}", b)
	}
}

// The three weights are one value. Each field is omitempty and all-three-zero
// reads as "unset", so patching exactly one of them to 0 ("stop counting
// throughput") would produce a document the gateway resolves straight back to
// the defaults — the term the user just turned off comes back on, silently.
// Caught by running the command against a real gateway, not by the unit tests.
func TestZeroingOneWeightNeedsTheOthersMaterialised(t *testing.T) {
	if !zeroWeights(apitypes.ProxyScoring{WeightThroughput: 0}) {
		t.Fatal("a lone explicit 0 must be recognised as an all-zero document")
	}
	if zeroWeights(apitypes.ProxyScoring{WeightLatency: 30}) {
		t.Fatal("a document with one non-zero weight is not all-zero")
	}
}

// Warm-up must be legible in the fixed-width table too: the longest cell
// ("100 (warming 0/10)") has to fit its column, or the row misaligns exactly
// when the reader is trying to compare nodes.
func TestScoreTextFitsItsColumn(t *testing.T) {
	got := scoreText(apitypes.ProxyScore{Score: 100, Warming: true, MinSamples: 10})
	if got != "100 (warming 0/10)" {
		t.Fatalf("warming score = %q", got)
	}
	if len(got) > scoreColWidth {
		t.Fatalf("score cell %q is %d wide, column is %d", got, len(got), scoreColWidth)
	}
	if s := scoreText(apitypes.ProxyScore{Score: 72.4}); s != "72" {
		t.Fatalf("measured score = %q", s)
	}
}
