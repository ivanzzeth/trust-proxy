package whitelist

import "testing"

func TestMatches_DomainSuffix(t *testing.T) {
	r := Rules{Domains: []string{"example.com", "*.wild.test"}}
	if !Matches(r, "example.com", "1.1.1.1:443") {
		t.Fatal("exact domain")
	}
	if !Matches(r, "a.example.com", "1.1.1.1:443") {
		t.Fatal("suffix")
	}
	if Matches(r, "notexample.com", "1.1.1.1:443") {
		t.Fatal("should not match sibling")
	}
	if !Matches(r, "wild.test", "1.1.1.1:443") {
		t.Fatal("*.wild.test covers apex")
	}
	if !Matches(r, "x.wild.test", "1.1.1.1:443") {
		t.Fatal("*.wild.test covers subdomain")
	}
}

func TestMatches_IP(t *testing.T) {
	r := Rules{IPs: []string{"203.0.113.5", "198.51.100.0/24"}}
	if !Matches(r, "", "203.0.113.5:443") {
		t.Fatal("exact IP")
	}
	if !Matches(r, "", "198.51.100.9:80") {
		t.Fatal("CIDR")
	}
	if Matches(r, "", "8.8.8.8:53") {
		t.Fatal("unlisted IP")
	}
}
