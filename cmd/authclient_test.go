package cmd

import "testing"

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
