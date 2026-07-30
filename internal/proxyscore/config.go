package proxyscore

import (
	"fmt"
	"strings"
)

// Tuning defaults. Every one of them is a knob in Config; a zero field means
// "unset" and resolves to the constant here, so an older store, an omitted JSON
// field, or a downgraded profile snapshot all keep working.
const (
	// DefaultMinSamples is how many real dial outcomes a node must accumulate
	// before its score stops being the neutral 100. Cold start must not judge:
	// one unlucky dial during a network change should never demote a node that
	// the whole gateway may be about to depend on.
	DefaultMinSamples = 10

	// Weights of the three terms. They are relative, not percentages — the
	// score divides by their sum, so 50/30/20 and 5/3/2 behave identically.
	DefaultWeightReliability = 50
	DefaultWeightLatency     = 30
	DefaultWeightThroughput  = 20

	// Streak amplification. The Nth consecutive failure costs N× the first one
	// (capped at MaxStreak), and the same for rewards. This is what makes the
	// score react hard to a node that is genuinely down while shrugging off a
	// single blip — and it stays explainable, because the UI can print the
	// current streak next to the score.
	DefaultRewardPerSuccess  = 2
	DefaultPenaltyPerFailure = 8
	DefaultMaxStreak         = 5

	// Latency term: <=Good ms scores 100, >=Bad ms scores 0, linear between.
	DefaultLatencyGoodMS = 80
	DefaultLatencyBadMS  = 800

	// Throughput term: KB/s that scores 100. Nodes with too little data moved
	// score a neutral 50 instead (see minThroughputBytes).
	DefaultThroughputGoodKBps = 2000

	// TieMargin: score differences smaller than this are "the same score", and
	// the tie is broken by latency — the user's rule, "相同分数选择延迟最低的".
	DefaultTieMarginPoints = 5

	// Circuit breaker (failsafe-go). Orthogonal to the score: it answers "can
	// this node be used right now", and it works from sample #1, which is what
	// stops a dead node from riding its warm-up 100 into selection.
	DefaultBreakerFailures     = 5
	DefaultBreakerDelaySeconds = 30
	DefaultBreakerSuccesses    = 2

	// StaleHours discards observations older than this on load. After a
	// subscription change or a move to another network, yesterday's numbers
	// describe a different path entirely.
	DefaultStaleHours = 6

	// DefaultBlackholeStreak is how many consecutive "handshake completed, we
	// sent bytes, nothing came back" connections confirm a node as a blackhole.
	// Subscriptions ship these: the provider's host answers its own handshake so
	// the dial succeeds, but nothing is relayed. Three rather than one because a
	// fire-and-forget push legitimately produces a single such connection; three
	// in a row on the same node does not happen to a node that works.
	DefaultBlackholeStreak = 3
)

// maxBreakerTrip bounds forceBreakerOpen's loop. It only needs BreakerFailures
// iterations, but the loop must terminate even if a future failsafe-go changes
// when RecordFailure advances state.
const maxBreakerTrip = 64

// minThroughputBytes is the floor for a transfer to count as a throughput
// sample. A 200-byte request that finishes in 300ms is not a slow node, it is
// a small request; letting it in would make chatty destinations look terrible.
const minThroughputBytes = 64 * 1024

// maxSeries caps the per-tag latency/throughput windows. Median over the last
// N samples, so one outlier cannot move the score and a recovered node is not
// held down by an hour-old disaster.
const maxSeries = 20

// Config is the operator-tunable scoring policy. It lives in
// proxygroups.Config.Scoring (same subject: how urltest picks a member) so it
// rides the existing profile/posture snapshot pipeline.
//
// Disabled (not Enabled) is the flag, so the zero value means "scoring on with
// stock defaults" — the behaviour a fresh install should get.
type Config struct {
	Disabled bool `json:"disabled,omitempty"`

	MinSamples int `json:"min_samples,omitempty"`

	WeightReliability int `json:"weight_reliability,omitempty"`
	WeightLatency     int `json:"weight_latency,omitempty"`
	WeightThroughput  int `json:"weight_throughput,omitempty"`

	RewardPerSuccess  int `json:"reward_per_success,omitempty"`
	PenaltyPerFailure int `json:"penalty_per_failure,omitempty"`
	MaxStreak         int `json:"max_streak,omitempty"`

	LatencyGoodMS int `json:"latency_good_ms,omitempty"`
	LatencyBadMS  int `json:"latency_bad_ms,omitempty"`

	ThroughputGoodKBps int `json:"throughput_good_kbps,omitempty"`

	TieMarginPoints int `json:"tie_margin_points,omitempty"`

	BreakerFailures     int `json:"breaker_failures,omitempty"`
	BreakerDelaySeconds int `json:"breaker_delay_seconds,omitempty"`
	BreakerSuccesses    int `json:"breaker_successes,omitempty"`

	StaleHours int `json:"stale_hours,omitempty"`

	// BlackholeStreak confirms a blackhole after this many consecutive dead
	// connections. -1 disables the detection entirely (0 means "unset" and
	// resolves to the default, like every other field here).
	BlackholeStreak int `json:"blackhole_streak,omitempty"`
}

func orDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// Resolved returns a copy with every unset field filled in, so callers (API,
// CLI, UI) can render the values that are actually in force rather than a row
// of blanks the user has to guess at.
func (c Config) Resolved() Config {
	return Config{
		Disabled:            c.Disabled,
		MinSamples:          c.Samples(),
		WeightReliability:   c.WRel(),
		WeightLatency:       c.WLat(),
		WeightThroughput:    c.WTp(),
		RewardPerSuccess:    c.Reward(),
		PenaltyPerFailure:   c.Penalty(),
		MaxStreak:           c.Streak(),
		LatencyGoodMS:       c.LatGood(),
		LatencyBadMS:        c.LatBad(),
		ThroughputGoodKBps:  c.TpGood(),
		TieMarginPoints:     c.TieMargin(),
		BreakerFailures:     c.BreakFails(),
		BreakerDelaySeconds: c.BreakDelay(),
		BreakerSuccesses:    c.BreakOKs(),
		StaleHours:          c.Stale(),
		BlackholeStreak:     c.Blackhole(),
	}
}

// Blackhole resolves the blackhole streak. Returns 0 when the operator disabled
// it with -1, since every read site treats 0 as "off".
func (c Config) Blackhole() int {
	if c.BlackholeStreak < 0 {
		return 0
	}
	return orDefault(c.BlackholeStreak, DefaultBlackholeStreak)
}

func (c Config) Samples() int { return orDefault(c.MinSamples, DefaultMinSamples) }

// WRel/WLat/WTp resolve the weights. Weights may legitimately be 0 ("ignore
// throughput entirely"), so an explicit 0 must survive — but all three at 0
// would divide by zero, which validate() rejects and sanitize() repairs.
func (c Config) WRel() int {
	if c.zeroWeights() {
		return DefaultWeightReliability
	}
	return c.WeightReliability
}

func (c Config) WLat() int {
	if c.zeroWeights() {
		return DefaultWeightLatency
	}
	return c.WeightLatency
}

func (c Config) WTp() int {
	if c.zeroWeights() {
		return DefaultWeightThroughput
	}
	return c.WeightThroughput
}

func (c Config) zeroWeights() bool {
	return c.WeightReliability <= 0 && c.WeightLatency <= 0 && c.WeightThroughput <= 0
}

func (c Config) Reward() int     { return orDefault(c.RewardPerSuccess, DefaultRewardPerSuccess) }
func (c Config) Penalty() int    { return orDefault(c.PenaltyPerFailure, DefaultPenaltyPerFailure) }
func (c Config) Streak() int     { return orDefault(c.MaxStreak, DefaultMaxStreak) }
func (c Config) LatGood() int    { return orDefault(c.LatencyGoodMS, DefaultLatencyGoodMS) }
func (c Config) LatBad() int     { return orDefault(c.LatencyBadMS, DefaultLatencyBadMS) }
func (c Config) TpGood() int     { return orDefault(c.ThroughputGoodKBps, DefaultThroughputGoodKBps) }
func (c Config) TieMargin() int  { return orDefault(c.TieMarginPoints, DefaultTieMarginPoints) }
func (c Config) BreakFails() int { return orDefault(c.BreakerFailures, DefaultBreakerFailures) }
func (c Config) BreakDelay() int {
	return orDefault(c.BreakerDelaySeconds, DefaultBreakerDelaySeconds)
}
func (c Config) BreakOKs() int { return orDefault(c.BreakerSuccesses, DefaultBreakerSuccesses) }
func (c Config) Stale() int    { return orDefault(c.StaleHours, DefaultStaleHours) }

// Formula renders the scoring formula with the weights currently in force. The
// UI puts this next to the live per-term values so "why is this node at 62"
// can be answered by looking, not by reading source.
func (c Config) Formula() string {
	sum := c.WRel() + c.WLat() + c.WTp()
	var b strings.Builder
	fmt.Fprintf(&b, "score = (%d×reliability + %d×latency + %d×throughput) / %d",
		c.WRel(), c.WLat(), c.WTp(), sum)
	return b.String()
}

// Validate rejects settings that would divide by zero, invert the latency
// mapping, or make scoring incapable of ever reacting. Called on every write so
// a bad value cannot reach the data plane.
func (c Config) Validate() error {
	neg := []struct {
		name string
		v    int
	}{
		{"min_samples", c.MinSamples},
		{"weight_reliability", c.WeightReliability},
		{"weight_latency", c.WeightLatency},
		{"weight_throughput", c.WeightThroughput},
		{"reward_per_success", c.RewardPerSuccess},
		{"penalty_per_failure", c.PenaltyPerFailure},
		{"max_streak", c.MaxStreak},
		{"latency_good_ms", c.LatencyGoodMS},
		{"latency_bad_ms", c.LatencyBadMS},
		{"throughput_good_kbps", c.ThroughputGoodKBps},
		{"tie_margin_points", c.TieMarginPoints},
		{"breaker_failures", c.BreakerFailures},
		{"breaker_delay_seconds", c.BreakerDelaySeconds},
		{"breaker_successes", c.BreakerSuccesses},
		{"stale_hours", c.StaleHours},
	}
	for _, f := range neg {
		if f.v < 0 {
			return fmt.Errorf("scoring: %s must not be negative", f.name)
		}
	}
	if c.MinSamples > 1000 {
		return fmt.Errorf("scoring: min_samples must be at most 1000")
	}
	if c.LatGood() >= c.LatBad() {
		return fmt.Errorf("scoring: latency_good_ms (%d) must be below latency_bad_ms (%d)", c.LatGood(), c.LatBad())
	}
	if c.TieMarginPoints > 100 {
		return fmt.Errorf("scoring: tie_margin_points must be at most 100")
	}
	if c.RewardPerSuccess > 100 || c.PenaltyPerFailure > 100 {
		return fmt.Errorf("scoring: reward/penalty must be at most 100 points")
	}
	if c.MaxStreak > 100 {
		return fmt.Errorf("scoring: max_streak must be at most 100")
	}
	if c.BreakerDelaySeconds > 3600 {
		return fmt.Errorf("scoring: breaker_delay_seconds must be at most 3600")
	}
	if c.StaleHours > 24*30 {
		return fmt.Errorf("scoring: stale_hours must be at most 720")
	}
	// Not in the negatives list above: -1 is the documented "off" for this one.
	if c.BlackholeStreak < -1 {
		return fmt.Errorf("scoring: blackhole_streak must be -1 (off), 0 (default) or positive")
	}
	if c.BlackholeStreak > 100 {
		return fmt.Errorf("scoring: blackhole_streak must be at most 100")
	}
	return nil
}
