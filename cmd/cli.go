package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/ivanzzeth/trust-proxy/pkg/client"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// Shared client-side plumbing for every CLI subcommand: where the backend is,
// and how results are printed. --json makes any command script-consumable
// (the raw wire shape, no table formatting).
var (
	apiAddr   string
	apiToken  string
	jsonOut   bool
	yesToAll  bool
	tableSkip = "-"
)

// addClientFlags registers the flags every backend-talking command shares.
func addClientFlags(cmds ...*cobra.Command) {
	for _, c := range cmds {
		f := c.PersistentFlags()
		if f.Lookup("api-addr") == nil {
			f.StringVar(&apiAddr, "api-addr", "127.0.0.1:21585", "backend API address")
		}
		if f.Lookup("api-token") == nil {
			f.StringVar(&apiToken, "api-token", "", "bearer token, when the backend runs with --api-token (probe mode)")
		}
		if f.Lookup("json") == nil {
			f.BoolVar(&jsonOut, "json", false, "print the raw JSON response instead of a table")
		}
	}
}

// resolveToken picks the credential to present: the --api-token flag, else
// TP_API_KEY from the environment.
//
// Nothing is read from disk on purpose. A cached credential file was the first
// design, and it went stale against a rebuilt registry and then turned an
// unclaimed gateway into a 401 — a secret at rest buying a footgun.
func resolveToken() string {
	if apiToken != "" {
		return apiToken
	}
	return os.Getenv("TP_API_KEY")
}

// loginToken is the credential `auth login` and `auth bootstrap` start from:
// nothing, unless one was passed by hand.
//
// TP_API_KEY is deliberately ignored there. Logging in is how you *replace* that
// key, and an exported one belonging to a deleted or revoked account made the
// login itself fail — "logged in, but minting an API key failed: unauthorized" —
// which reads as "my password is wrong" when it is not.
func loginToken() string { return apiToken }

// loginSDK is a client for the commands that establish a credential rather than
// use one.
func loginSDK() *client.Client {
	return client.New(client.Options{APIBaseURL: apiAddr, Token: loginToken()})
}

// emit prints v as indented JSON. Every command routes its result through
// printJSON/table so --json is honoured uniformly.
func emit(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// out prints the table form unless --json was given, in which case v is dumped.
func out(v any, table func()) error {
	if jsonOut {
		return emit(v)
	}
	table()
	return nil
}

// dash returns "-" for an empty string so table columns stay aligned.
func dash(s string) string {
	if s == "" {
		return tableSkip
	}
	return s
}

// yesNo renders a bool for a table cell.
func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// truncate keeps table rows on one line.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// confirm asks before an operation that changes the live data plane in a way
// that can cut connectivity (mode switches, posture flips). --yes skips it.
func confirm(prompt string) error {
	if yesToAll {
		return nil
	}
	fmt.Printf("%s [y/N] ", prompt)
	var answer string
	_, _ = fmt.Scanln(&answer)
	if strings.EqualFold(strings.TrimSpace(answer), "y") {
		return nil
	}
	return fmt.Errorf("aborted")
}
