package cmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/ivanzzeth/trust-proxy/pkg/client"
)

// `auth login` must authenticate with the password it was just given, not with
// whatever TP_API_KEY happens to be exported.
//
// Measured: after deleting the account an old key belonged to, `auth login` said
// "logged in, but minting an API key failed: unauthorized" — it had logged in
// fine and then presented the dead key for the next call. The server now prefers
// a valid session, and the client should not send the stale key at all: the whole
// point of logging in is to replace it.
func TestLoginClientIgnoresAnExportedKey(t *testing.T) {
	t.Setenv("TP_API_KEY", "tp_a-key-from-a-deleted-account")
	apiToken = ""
	if got := loginToken(); got != "" {
		t.Fatalf("login must start with no credential, got %q", got)
	}
	// An explicit --api-token is different: the operator asked for it by hand.
	apiToken = "explicit"
	defer func() { apiToken = "" }()
	if got := loginToken(); got != "explicit" {
		t.Fatalf("an explicit --api-token must still be used, got %q", got)
	}
}

// A bare 401 is not an error anyone can act on, and three different situations
// produce it. The decoration has to say which.
func TestUnauthorizedErrorTellsYouHowToAuthenticate(t *testing.T) {
	unauthorized := &client.APIError{Method: "GET", Path: "/api/users", Status: 401, Message: "unauthorized"}

	// Nothing in hand: say how to get something.
	err := decorateAuthError(unauthorized, "")
	if err == nil {
		t.Fatal("expected the error to survive")
	}
	if !strings.Contains(err.Error(), "auth login") {
		t.Fatalf("the hint must point at logging in: %v", err)
	}
	// The original must still be reachable, or `errors.As` upstream stops working.
	if !client.IsUnauthorized(err) {
		t.Fatalf("decoration must wrap, not replace: %v", err)
	}

	// A credential that was refused: logging in again is right, telling someone who
	// already has a key how to get one is noise.
	withKey := decorateAuthError(unauthorized, "tp_something")
	if strings.Contains(withKey.Error(), "nothing is stored") {
		t.Fatalf("should not tell someone who already has a credential that they have none: %v", withKey)
	}
	if !strings.Contains(withKey.Error(), "revoked") {
		t.Fatalf("a refused credential should be named as such: %v", withKey)
	}
}

// Decoration keys off the *status*, not off the prose. A substring match on
// "unauthorized" both misses a reworded message and fires on unrelated errors
// that happen to contain the word — and this decorator wraps every command's
// result, including the gateway's own.
func TestOnlyA401IsDecorated(t *testing.T) {
	for _, err := range []error{
		&client.APIError{Method: "POST", Path: "/api/whitelist", Status: 400, Message: "invalid ip_cidr"},
		// The word, in something that is not an authentication failure at all.
		&client.APIError{Method: "POST", Path: "/api/acl", Status: 400, Message: "rule name 'unauthorized' is reserved"},
		errors.New("listen tcp 127.0.0.1:21585: bind: address already in use"),
	} {
		if got := decorateAuthError(err, ""); got.Error() != err.Error() {
			t.Fatalf("decorated something that is not a 401:\n  in:  %v\n  out: %v", err, got)
		}
	}
	if decorateAuthError(nil, "") != nil {
		t.Fatal("a nil error must stay nil")
	}
}
