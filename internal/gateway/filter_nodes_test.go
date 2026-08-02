package gateway

import (
	"encoding/json"
	"testing"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func TestFilterEligibleNodes_DropsJunkAndDisabled(t *testing.T) {
	mk := func(tag, server string, port int) apitypes.Node {
		ob, _ := json.Marshal(map[string]any{
			"type": "shadowsocks", "tag": tag, "server": server, "server_port": port,
			"method": "aes-128-gcm", "password": "x",
		})
		return apitypes.Node{Tag: tag, Protocol: "shadowsocks", Server: server, Port: port, Outbound: ob}
	}
	nodes := []apitypes.Node{
		mk("🇭🇰 Hong Kong丨01", "real.example", 443),
		mk("跳转域名{请勿连接}:nflink.info", "123.123.213.213", 53),
		mk("35.77 GB | 300 GB", "real.example", 601),
		mk("新加坡 C", "sasia.example", 739),
		mk("台湾", "tw.example", 12001),
	}
	got := FilterEligibleNodes(nodes, map[string]bool{"新加坡 C": true})
	tags := memberTags(got, nil)
	want := map[string]bool{"🇭🇰 Hong Kong丨01": true, "台湾": true}
	if len(tags) != 2 {
		t.Fatalf("eligible=%v, want HK + 台湾", tags)
	}
	for _, tag := range tags {
		if !want[tag] {
			t.Fatalf("unexpected eligible tag %q in %v", tag, tags)
		}
	}
}
