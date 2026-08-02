package proxygroups

import "testing"

func TestIsJunkNode_LiveFingerprints(t *testing.T) {
	cases := []struct {
		tag, server string
		port        int
		junk        bool
	}{
		{"跳转域名{请勿连接}:nflink.info", "123.123.213.213", 53, true},
		{"剩余流量：1003.8 GB", "123.123.213.213", 53, true},
		{"距离下次重置剩余：17 天", "123.123.213.213", 53, true},
		{"套餐到期：2027-03-17", "123.123.213.213", 53, true},
		{"35.77 GB | 300 GB", "wgnxasf62w.hss16lexbb.sbs", 601, true},
		{"Traffic Reset: 25 Days Left", "wgnxasf62w.hss16lexbb.sbs", 601, true},
		{"Expire Date: 2027-07-23", "wgnxasf62w.hss16lexbb.sbs", 601, true},
		// Placeholder server alone is enough — even with a normal-looking tag.
		{"promo-line", "123.123.213.213", 443, true},
		// Real nodes must stay selectable.
		{"🇭🇰 Hong Kong丨01", "wgnxasf62w.hss16lexbb.sbs", 601, false},
		{"台湾", "orbitwcn01.orbit-links.com", 12001, false},
		{"新加坡 C", "sasia-cloud9.orbit-links.com", 739, false},
		{"[hy2]香港 1 直连", "hktv01.outleft-hy.xyz", 543, false},
	}
	for _, tc := range cases {
		got, reason := IsJunkNode(tc.tag, tc.server, tc.port)
		if got != tc.junk {
			t.Errorf("IsJunkNode(%q,%q,%d)=%v (%s), want junk=%v",
				tc.tag, tc.server, tc.port, got, reason, tc.junk)
		}
		if got && reason == "" {
			t.Errorf("junk node %q must report a reason", tc.tag)
		}
	}
}
