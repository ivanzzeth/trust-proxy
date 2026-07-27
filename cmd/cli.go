package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ivanzzeth/trust-proxy/internal/credentials"
	"github.com/ivanzzeth/trust-proxy/pkg/client"
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

// resolveToken picks the credential to present, most explicit first: the
// --api-token flag, then TP_API_KEY, then the stored one for this gateway.
//
// The stored file is back, and this time it carries the gateway id it was minted
// against. Its first incarnation was deleted because it went stale against a
// rebuilt registry and produced a 401 nobody could explain — but the answer to
// that was never "keep no credential and make everyone paste
// `eval "$(… | grep ^export)"` into their shell forever". It is to notice the
// staleness and say so, which is what decorateAuthError does below.
func resolveToken() string {
	if apiToken != "" {
		return apiToken
	}
	if k := os.Getenv("TP_API_KEY"); k != "" {
		return k
	}
	e, ok := storedCredential()
	if !ok {
		return ""
	}
	return e.Key
}

// storedCredential is the saved entry for the gateway this command is aimed at.
func storedCredential() (credentials.Entry, bool) {
	path, err := credentials.Path()
	if err != nil {
		return credentials.Entry{}, false
	}
	return credentials.Get(path, apiAddr)
}

// rememberCredential saves a freshly minted key for this gateway, so the next
// command needs no flag, no environment variable and no ceremony.
func rememberCredential(e credentials.Entry) (string, error) {
	path, err := credentials.Path()
	if err != nil {
		return "", err
	}
	if err := credentials.Put(path, apiAddr, e); err != nil {
		return "", err
	}
	return path, nil
}

// decorateAuthError turns a 401 into something the caller can act on.
//
// Three different situations produce the same status code and want opposite
// advice: nothing to present, a key that belongs to a gateway that has since been
// reinstalled, and a key that was revoked. Telling them apart costs one public
// request on the failure path, and saves the guessing that this project has
// already paid for twice.
func decorateAuthError(err error, credential string) error {
	if err == nil || !client.IsUnauthorized(err) {
		return err
	}
	if credential == "" {
		return fmt.Errorf("%w\n\nnot authenticated, and nothing is stored for %s.\n"+
			"    trust-proxy auth login <name> --api-addr %s\n"+
			"which saves the key for next time. On the gateway's own machine, an unclaimed\n"+
			"one is claimed with:  sudo trust-proxy install", err, apiAddr, apiAddr)
	}
	if stored, ok := storedCredential(); ok && stored.Key == credential && stored.GatewayID != "" {
		if st, sErr := sdkAnonymous().AuthState(); sErr == nil && st.GatewayID != "" && st.GatewayID != stored.GatewayID {
			return fmt.Errorf("%w\n\nthe gateway on %s is not the one this key was minted against —\n"+
				"it has been reinstalled, or its data directory was replaced. Log in again:\n"+
				"    trust-proxy auth login <name> --api-addr %s", err, apiAddr, apiAddr)
		}
	}
	return fmt.Errorf("%w\n\nthe credential in use was refused — it may have been revoked, or belong to a "+
		"deleted account. Log in again: trust-proxy auth login <name> --api-addr %s", err, apiAddr)
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

// sdkAnonymous carries no credential, for the public endpoints used while
// working out *why* a credential was refused.
func sdkAnonymous() *client.Client {
	return client.New(client.Options{APIBaseURL: apiAddr})
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
