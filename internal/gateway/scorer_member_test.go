package gateway

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/ivanzzeth/trust-proxy/internal/detect"
	"github.com/ivanzzeth/trust-proxy/internal/proxyscore"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// node builds a subscription node the way the stores hold one: memberTags reads
// the tag out of the outbound JSON, so a node without it has no tag at all.
func scoreNode(tag string) apitypes.Node {
	ob, _ := json.Marshal(map[string]any{"type": "anytls", "tag": tag, "server": "x.example", "server_port": 443})
	return apitypes.Node{Tag: tag, Server: "x.example", Port: 443, Outbound: ob}
}

func scoringManager(t *testing.T, members []apitypes.Node) *Manager {
	t.Helper()
	m := &Manager{scores: proxyscore.New(filepath.Join(t.TempDir(), "scores.json"), proxyscore.Config{})}
	m.setEligibleMembers(members, nil)
	if len(*m.eligible.Load()) == 0 {
		t.Fatal("precondition: the eligible set is empty, which allows everything")
	}
	return m
}

func scoreRow(t *testing.T, m *Manager, tag string) (proxyscore.View, bool) {
	t.Helper()
	for _, v := range m.scores.Snapshot([]string{tag}) {
		if v.Tag == tag {
			return v, v.Samples > 0 || v.BlackholeStreak > 0 || v.UpdatedAt != ""
		}
	}
	return proxyscore.View{}, false
}

// A proxy GROUP must never collect score evidence. Measured on a live gateway:
// the country groups `🇺🇸 US` and `🇯🇵 JP` had records with blackhole_streak 2
// and 1 — two more such connections and the blackhole verdict would have
// condemned the group itself (score 0, breaker forced open). A pinned rule
// targets exactly those groups (Claude → US), so the condemned thing would have
// been the user's chosen exit while every member of it kept working.
//
// It gets in because a connection is tracked when it starts: right after a
// rebuild the group has not elected anyone, Now() is empty, and outStr falls
// back to the group's own tag.
func TestGroupTagsAreNotScored(t *testing.T) {
	m := scoringManager(t, []apitypes.Node{scoreNode("🇺🇸 United States丨01"), scoreNode("🇺🇸 United States丨02")})

	// The blackhole shape: handshake ok, bytes up, nothing back.
	for i := 0; i < 5; i++ {
		m.RecordEvent(detect.Event{
			Outbound: "🇺🇸 US", Upload: 1 << 20, Download: 0,
			DurationMS: 5000, Connected: true,
		})
	}
	if _, seen := scoreRow(t, m, "🇺🇸 US"); seen {
		t.Fatal("the country group 🇺🇸 US collected score evidence; one more and the group itself is condemned")
	}

	// The same evidence about a real member must land.
	for i := 0; i < 5; i++ {
		m.RecordEvent(detect.Event{
			Outbound: "anytls/🇺🇸 United States丨01", Upload: 1 << 20, Download: 0,
			DurationMS: 5000, Connected: true,
		})
	}
	v, seen := scoreRow(t, m, "🇺🇸 United States丨01")
	if !seen {
		t.Fatal("a real member's blackhole evidence was dropped")
	}
	if v.BlackholeStreak == 0 {
		t.Fatalf("member blackhole streak not counted: %+v", v)
	}
}

// Every scoring entry point is gated, not just the finalize sink: a stall kill or
// a Clash delay probe naming a group would demote it just as effectively.
func TestEveryScoringEntryPointRejectsNonMembers(t *testing.T) {
	m := scoringManager(t, []apitypes.Node{scoreNode("node-a")})

	m.NoteProbe("🇯🇵 JP", true, 100*time.Millisecond)
	m.RecordStreamStall("🇯🇵 JP")
	m.RecordTransfer("🇯🇵 JP", proxyscore.Transfer{Upload: 1 << 20, Duration: time.Second, Handshook: true})
	m.RecordEvent(detect.Event{Outbound: "🇯🇵 JP", Upload: 1 << 20, DurationMS: 3000, Connected: true})

	if _, seen := scoreRow(t, m, "🇯🇵 JP"); seen {
		t.Fatal("a group tag reached the score store through one of the entry points")
	}
}

// The type prefix detector.outStr adds must not make a member look foreign.
func TestMembershipCheckNormalizesTheTypePrefix(t *testing.T) {
	m := scoringManager(t, []apitypes.Node{scoreNode("tokyo-01")})
	if !m.scorableMember("anytls/tokyo-01") {
		t.Fatal("a member became unscorable once outStr prefixed its type")
	}
	if m.scorableMember("anytls/osaka-09") {
		t.Fatal("an unknown tag passed the membership check")
	}
}

// Before the first rebuild there is no member list, and dropping the first
// connections of a gateway's life would be worse than accepting a stale tag.
func TestScoringAllowsEverythingBeforeTheFirstRebuild(t *testing.T) {
	m := &Manager{scores: proxyscore.New(filepath.Join(t.TempDir(), "scores.json"), proxyscore.Config{})}
	if !m.scorableMember("anything") {
		t.Fatal("scoring was gated before the member list existed")
	}
}

// Disabled and junk members are not eligible, so the snapshot rebuild takes them
// out of scoring as a side effect of the list it is built from.
func TestEligibleSnapshotFollowsFilterEligibleNodes(t *testing.T) {
	nodes := []apitypes.Node{scoreNode("live-01"), scoreNode("35.77 GB | 300 GB")}
	kept := FilterEligibleNodes(nodes, nil)
	m := scoringManager(t, kept)
	if !m.scorableMember("live-01") {
		t.Fatal("a live member is not scorable")
	}
	if m.scorableMember("35.77 GB | 300 GB") {
		t.Fatal("an airport quota line is scorable")
	}
}

// A subscription ships rows shaped like proxies that are really quota text.
// They are kept out of every urltest group, so they can never carry a byte — but
// the score list was built from the raw node list, and all three showed up at
// "100, preferred", indistinguishable from the best real exit in the table.
func TestScoreListDropsAirportInfoLines(t *testing.T) {
	m := &Manager{scores: proxyscore.New(filepath.Join(t.TempDir(), "scores.json"), proxyscore.Config{})}
	m.nodes = []apitypes.Node{
		scoreNode("🇯🇵 Japan丨01"),
		scoreNode("35.77 GB | 300 GB"),
		scoreNode("Expire Date: 2027-07-23"),
		scoreNode("Traffic Reset: 25 Days Left"),
	}

	got := map[string]bool{}
	for _, tag := range m.MemberTags() {
		got[tag] = true
	}
	if !got["🇯🇵 Japan丨01"] {
		t.Fatal("a real node is missing from the score list")
	}
	for _, junk := range []string{"35.77 GB | 300 GB", "Expire Date: 2027-07-23", "Traffic Reset: 25 Days Left"} {
		if got[junk] {
			t.Fatalf("airport info line %q is listed as a scorable member", junk)
		}
	}

	for _, v := range m.Scores(nil) {
		if v.Tag != "🇯🇵 Japan丨01" {
			t.Fatalf("score snapshot contains %q", v.Tag)
		}
	}
}

// A node the operator disabled is still a node: its history is usually why they
// disabled it, so it must not vanish from the table the way junk does.
func TestScoreListKeepsDisabledNodes(t *testing.T) {
	m := &Manager{scores: proxyscore.New(filepath.Join(t.TempDir(), "scores.json"), proxyscore.Config{})}
	m.nodes = []apitypes.Node{scoreNode("🇯🇵 Japan丨01"), scoreNode("🇭🇰 Hong Kong丨09")}
	m.disabledTags = map[string]bool{"🇭🇰 Hong Kong丨09": true}

	found := false
	for _, tag := range m.MemberTags() {
		if tag == "🇭🇰 Hong Kong丨09" {
			found = true
		}
	}
	if !found {
		t.Fatal("an operator-disabled node disappeared from the score list")
	}
}
