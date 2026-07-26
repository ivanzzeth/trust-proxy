package proxygen

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Deploy commands. A generated exit is only useful once someone runs the server
// half, and the two halves are one keypair: generating on the exit host means
// generating twice, and then the client node a console holds does not match the
// server that is running. So the console generates once and hands over a script
// that carries the config with it.
//
// Rendered here rather than in the API or the console so every surface prints
// the same text.

// DefaultConfigPath is where InstallScript writes the server config.
const DefaultConfigPath = "server.json"

// GenCommand renders the `trust-proxy proxy gen` invocation equivalent to o.
// Useful for showing "this is what the UI just did" — and for anyone who would
// rather generate on the exit host and paste the client node back by hand.
func GenCommand(o Options) string {
	parts := []string{"trust-proxy", "proxy", "gen", "--type", shQuote(o.Type)}
	if o.Server != "" {
		parts = append(parts, "--server", shQuote(o.Server))
	}
	if o.Port != 0 {
		parts = append(parts, "--port", strconv.Itoa(o.Port))
	}
	if o.SNI != "" {
		parts = append(parts, "--sni", shQuote(o.SNI))
	}
	if o.Name != "" {
		parts = append(parts, "--name", shQuote(o.Name))
	}
	return strings.Join(parts, " ")
}

// InstallScript renders what an operator pastes into a shell on the exit host:
// it writes the already-generated server config and starts it detached. path
// defaults to DefaultConfigPath.
//
// The heredoc delimiter is quoted so the shell expands nothing inside the JSON
// (keys are base64 and routinely contain $ and backticks).
func InstallScript(server map[string]any, path string) string {
	if path == "" {
		path = DefaultConfigPath
	}
	cfg, err := json.MarshalIndent(server, "", "  ")
	if err != nil {
		// Generate builds this map itself; an unmarshalable one is a programming
		// error, and a broken script is better than a silent empty one.
		cfg = []byte(fmt.Sprintf("{\"error\": %q}", err.Error()))
	}
	return strings.Join([]string{
		"# run on the exit host — needs the trust-proxy binary there (scp it over, or build from source)",
		"cat > " + shQuote(path) + " <<'TRUST_PROXY_EOF'",
		string(cfg),
		"TRUST_PROXY_EOF",
		"trust-proxy proxy run -c " + shQuote(path) + " -d",
	}, "\n")
}

// shQuote makes a value safe as a single shell word. Single quotes disable every
// expansion, and an embedded quote is closed, escaped and reopened — the usual
// POSIX trick, since a server name or node title is user input.
func shQuote(s string) string {
	if s == "" {
		return "''"
	}
	if strings.IndexFunc(s, func(r rune) bool {
		return !(r == '.' || r == '-' || r == '_' || r == '/' || r == ':' ||
			(r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
