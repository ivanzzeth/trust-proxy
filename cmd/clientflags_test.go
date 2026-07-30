package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// Every command that talks to a running backend has to carry --api-addr,
// --api-token and --json. They come from one place (addClientFlags, driven by
// the `clients` list in root.go), so the only way to get them wrong is to mount
// a command outside that list — which is exactly what happened to `inbound`,
// `retention` and `defaults`: they were added straight to rootCmd, built fine,
// ran fine against the default address, and answered "unknown flag: --api-addr"
// the moment anyone pointed them at another gateway. That reads as "this
// command does not exist", not "it is registered in the wrong list".
//
// Enumerating the client commands here would just be a second copy of the list
// that drifts the same way. Instead: anything that reaches the network does so
// through sdk(), so look for that in the source... which a test cannot do.
// The next best invariant that needs no list — a leaf command whose RunE is set
// and which is not one of the deliberately local ones must have the flags.
func TestBackendCommandsAllTakeTheClientFlags(t *testing.T) {
	// The local, privileged, or offline commands: they deliberately take no
	// --api-addr, because they must work when no gateway is running at all
	// (install/uninstall/serve), or they speak a different protocol entirely
	// (conn → Clash API, proxy → a local exit node).
	local := map[string]bool{
		"install": true, "uninstall": true, "serve": true, "conn": true,
		"proxy": true, "service": true, "selftest": true, "doctor": true,
		"version": true, "help": true, "completion": true,
	}

	var walk func(c *cobra.Command, root string)
	walk = func(c *cobra.Command, root string) {
		if local[root] {
			return
		}
		if c.Runnable() {
			for _, f := range []string{"api-addr", "api-token", "json"} {
				if !reachableFlag(c, f) {
					t.Errorf("`trust-proxy %s` cannot be pointed at a gateway: no --%s "+
						"(is it registered outside root.go's client list?)",
						strings.TrimPrefix(c.CommandPath(), "trust-proxy "), f)
				}
			}
		}
		for _, sub := range c.Commands() {
			walk(sub, root)
		}
	}
	for _, c := range rootCmd.Commands() {
		walk(c, c.Name())
	}
}

// A command that can prompt must offer --yes, or it cannot be scripted at all:
// the prompt reads a stdin a script does not have, and `-y` comes back as
// "unknown shorthand flag", which reads as "this command does not support that"
// rather than "the flag was never registered". `inbound set` shipped that way —
// and it prompts before an off-loopback bind, the change most likely to be made
// from an install script in the first place.
//
// Found by parsing this package rather than by listing the prompting commands,
// because such a list goes stale exactly when a new one is added — which is the
// only moment the test would have earned its keep. The flag side is checked on
// the live command, so it does not care whether --yes was registered singly, in
// a loop, or through an `f := cmd.Flags()` helper (all three are in use here).
func TestPromptingCommandsOfferYes(t *testing.T) {
	prompts := promptingCommands(t)
	if len(prompts) < 3 {
		t.Fatalf("found only %d prompting commands; the source scan is probably broken, "+
			"and a broken scan passes silently", len(prompts))
	}
	for _, c := range prompts {
		if !reachableFlag(c, "yes") {
			t.Errorf("`%s` prompts for confirmation but has no --yes/-y: it cannot be run "+
				"from a script, and -y fails as an unknown flag rather than as a refusal", c.CommandPath())
		}
	}
}

// promptingCommands parses the package for `var xxxCmd = &cobra.Command{…}`
// declarations whose body calls confirm(), then resolves each to the live
// command via the `parent.AddCommand(xxxCmd)` calls in the same source.
func promptingCommands(t *testing.T) []*cobra.Command {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	pkg := pkgs["cmd"]
	if pkg == nil {
		t.Fatal("cmd package did not parse")
	}

	use := map[string]string{}       // var name -> Use, first word
	parent := map[string]string{}    // var name -> parent var name
	confirms := map[string]bool{}    // var name -> body calls confirm()
	for _, f := range pkg.Files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.ValueSpec:
				for i, name := range node.Names {
					if i >= len(node.Values) {
						break
					}
					lit := commandLiteral(node.Values[i])
					if lit == nil {
						continue
					}
					use[name.Name] = firstWord(litField(lit, "Use"))
					if callsConfirm(lit) {
						confirms[name.Name] = true
					}
				}
			case *ast.CallExpr:
				sel, ok := node.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "AddCommand" {
					return true
				}
				recv, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				for _, arg := range node.Args {
					if id, ok := arg.(*ast.Ident); ok {
						parent[id.Name] = recv.Name
					}
				}
			}
			return true
		})
	}

	var out []*cobra.Command
	for name := range confirms {
		var path []string
		for n := name; n != "" && n != "rootCmd"; n = parent[n] {
			if use[n] == "" {
				path = nil
				break
			}
			path = append([]string{use[n]}, path...)
		}
		if len(path) == 0 {
			continue // not mounted under root, or built somewhere this scan cannot see
		}
		c, _, err := rootCmd.Find(path)
		if err != nil || c == rootCmd {
			continue
		}
		out = append(out, c)
	}
	return out
}

func commandLiteral(e ast.Expr) *ast.CompositeLit {
	u, ok := e.(*ast.UnaryExpr)
	if !ok {
		return nil
	}
	lit, ok := u.X.(*ast.CompositeLit)
	if !ok {
		return nil
	}
	sel, ok := lit.Type.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Command" {
		return nil
	}
	return lit
}

func litField(lit *ast.CompositeLit, field string) string {
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if k, ok := kv.Key.(*ast.Ident); !ok || k.Name != field {
			continue
		}
		if s, ok := kv.Value.(*ast.BasicLit); ok && s.Kind == token.STRING {
			v, err := strconv.Unquote(s.Value)
			if err == nil {
				return v
			}
		}
	}
	return ""
}

func firstWord(s string) string {
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i]
	}
	return s
}

func callsConfirm(lit *ast.CompositeLit) bool {
	found := false
	ast.Inspect(lit, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "confirm" {
			found = true
		}
		return !found
	})
	return found
}

// reachableFlag reports whether `name` is usable on c, walking up to the root
// for persistent flags declared on a parent.
//
// Deliberately not cobra's InheritedFlags(): that one *builds* the inherited
// set by merging parents into a cached flagset, and a later VisitAll over the
// command then sees flags it did not declare. TestScoringFlagListMatchesRegistered
// counts exactly that, so calling InheritedFlags here made an unrelated test fail
// depending on which ran first.
func reachableFlag(c *cobra.Command, name string) bool {
	if c.Flags().Lookup(name) != nil {
		return true
	}
	for p := c; p != nil; p = p.Parent() {
		if p.PersistentFlags().Lookup(name) != nil {
			return true
		}
	}
	return false
}
