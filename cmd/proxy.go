package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/spf13/cobra"

	singjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/ivanzzeth/trust-proxy/internal/proxygen"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Run or generate a proxy SERVER (self-hosted exit node)",
}

// ---- proxy run ----

var (
	proxyRunConfig string
	proxyDaemon    bool
	proxyLog       string
	proxyPid       string
)

var proxyRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run a sing-box server config (inbound protocol -> direct out)",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Built-in daemon: re-exec detached (survives SSH logout) unless we're
		// already the daemon child.
		if proxyDaemon && os.Getenv("TP_DAEMON") == "" {
			return daemonize(proxyLog, proxyPid)
		}

		content, err := os.ReadFile(proxyRunConfig)
		if err != nil {
			return err
		}
		ctx := service.ContextWith(context.Background(), deprecated.NewStderrManager(log.StdLogger()))
		ctx = include.Context(ctx)
		options, err := singjson.UnmarshalExtendedContext[option.Options](ctx, content)
		if err != nil {
			return err
		}
		inst, err := box.New(box.Options{Context: ctx, Options: options})
		if err != nil {
			return err
		}
		if err := inst.Start(); err != nil {
			return err
		}
		defer inst.Close()
		log.StdLogger().Info("proxy server started")
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		return nil
	},
}

// ---- proxy gen ----

var (
	genType   string
	genPort   int
	genServer string
	genSNI    string
	genName   string
	genOut    string
)

// gen runs locally rather than through the SDK: an exit node is generated on
// laptops and jump hosts where no gateway is running, so requiring a daemon
// would be backwards. /api/proxy-gen exists for the console and wraps the same
// proxygen package, so the two surfaces cannot drift.
var proxyGenCmd = &cobra.Command{
	Use:   "gen",
	Short: "One-click generate a server config + client node for any protocol",
	Long:  "Supported --type: " + strings.Join(proxygen.Protocols, " | "),
	RunE: func(cmd *cobra.Command, args []string) error {
		opts := proxygen.Options{Type: genType, Server: genServer, Port: genPort, SNI: genSNI, Name: genName}
		res, err := proxygen.Generate(opts)
		if err != nil {
			return err
		}
		if jsonOut {
			// Same shape as POST /api/proxy-gen, so a script can consume either.
			return emit(apitypes.ProxyGenResult{
				Server: res.Server, Client: res.Client, Share: res.Share,
				GenCommand:    proxygen.GenCommand(opts),
				InstallScript: proxygen.InstallScript(res.Server, genOut),
			})
		}
		srvJSON, _ := json.MarshalIndent(res.Server, "", "  ")
		if genOut != "" {
			if err := os.WriteFile(genOut, srvJSON, 0o644); err != nil {
				return err
			}
			fmt.Printf("✓ server config -> %s\n  run it:  trust-proxy proxy run -c %s\n\n", genOut, genOut)
		} else {
			fmt.Printf("=== server config (trust-proxy proxy run -c <file>) ===\n%s\n\n", srvJSON)
			// Generating twice would mint a second keypair, so hand over the config
			// rather than telling people to re-run gen on the exit host.
			fmt.Printf("=== deploy on the exit host (paste as-is) ===\n%s\n\n", proxygen.InstallScript(res.Server, genOut))
		}
		clashJSON, _ := json.MarshalIndent(res.Client, "", "  ")
		fmt.Printf("=== client node — paste into trust-proxy (Nodes → Paste, or the console's Self-hosted exit dialog) ===\n%s\n", clashJSON)
		if res.Share != "" {
			fmt.Printf("\n=== client share link ===\n%s\n", res.Share)
		}
		return nil
	},
}

var proxyStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop a daemonized proxy server (reads --pid file)",
	RunE: func(cmd *cobra.Command, args []string) error {
		pid, err := readPidFile(proxyPid)
		if err != nil {
			return fmt.Errorf("read pid file %s: %w", proxyPid, err)
		}
		alive, confirmedOther := checkPid(pid)
		if !alive {
			_ = os.Remove(proxyPid)
			fmt.Printf("pid %d is not running (stale pid file removed)\n", pid)
			return nil
		}
		if confirmedOther {
			return fmt.Errorf("refusing to signal pid %d: it does not look like a trust-proxy process (pid file %s is likely stale/reused) — remove it manually if you're sure", pid, proxyPid)
		}
		p, err := os.FindProcess(pid)
		if err != nil {
			return err
		}
		if err := p.Signal(syscall.SIGTERM); err != nil {
			return fmt.Errorf("signal pid %d: %w", pid, err)
		}
		_ = os.Remove(proxyPid)
		fmt.Printf("stopped pid %d\n", pid)
		return nil
	},
}

func init() {
	proxyRunCmd.Flags().StringVarP(&proxyRunConfig, "config", "c", "server.json", "server config path")
	proxyRunCmd.Flags().BoolVarP(&proxyDaemon, "daemon", "d", false, "run in background (detached; survives SSH logout)")
	proxyRunCmd.Flags().StringVar(&proxyLog, "log", "trust-proxy.log", "daemon log file")
	proxyRunCmd.Flags().StringVar(&proxyPid, "pid", "trust-proxy.pid", "daemon pid file")
	proxyStopCmd.Flags().StringVar(&proxyPid, "pid", "trust-proxy.pid", "pid file to stop")
	f := proxyGenCmd.Flags()
	f.StringVar(&genType, "type", "vless-reality", strings.Join(proxygen.Protocols, " | "))
	f.IntVar(&genPort, "port", 443, "listen port")
	f.StringVar(&genServer, "server", "", "server address for the client link")
	f.StringVar(&genSNI, "sni", "", "TLS/Reality SNI (default www.microsoft.com)")
	f.StringVar(&genName, "name", "", "node name")
	f.StringVar(&genOut, "out", "", "write server config to file (default stdout)")
	// gen talks to no backend, so it takes --json alone rather than the shared
	// client flags: an --api-addr here would imply a daemon it never contacts.
	f.BoolVar(&jsonOut, "json", false, "print the raw JSON response instead of a table")
	proxyCmd.AddCommand(proxyRunCmd, proxyGenCmd, proxyStopCmd)
}
