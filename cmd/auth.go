package cmd

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/ivanzzeth/trust-proxy/internal/users"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Accounts from the command line, in two flavours — because a remote gateway has
// no browser:
//
// Everything here goes through the API. The gateway process is the only writer of
// users.json — a CLI that edited the file directly would be a second writer, and a
// running gateway would not see the change (measured: it kept reporting itself
// unclaimed).
//
// A headless box needs no special path for that: SSH means loopback, and loopback
// bootstrap needs no credential. Lost every admin password? Delete users.json — the
// gateway goes back to unclaimed. File access on the machine is the ultimate
// authority, and that is the only place it is exercised.
//
// Credentials are not cached anywhere: `auth login` prints an API key, you export
// TP_API_KEY (or pass --api-token). One less secret on disk, and no file that can
// go stale against a rebuilt registry — which is exactly what bit the first
// version of this.

// ---- auth (over the API) -------------------------------------------------

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Log in to a gateway, or claim a new one (over the API)",
}

var authBootstrapCode string

var authBootstrapCmd = &cobra.Command{
	Use:   "bootstrap <username>",
	Short: "Create the first admin on an unclaimed gateway",
	Long: "Creates the first account, which is always an admin.\n\n" +
		"From the machine itself no code is needed. Reaching a gateway over the network\n" +
		"needs --code, the one-time code printed in its log at startup — otherwise\n" +
		"whoever reaches the port first could claim it. On a headless box you can also\n" +
		"skip the API entirely: `trust-proxy user add <name> --admin`.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		pw, err := readNewPassword()
		if err != nil {
			return err
		}
		sess, err := sdk().Bootstrap(args[0], pw, authBootstrapCode)
		if err != nil {
			return err
		}
		return out(sess, func() {
			fmt.Printf("✓ %s created as admin on %s\n\n", sess.User.Username, apiAddr)
			fmt.Printf("  next:  trust-proxy auth login %s --api-addr %s\n", sess.User.Username, apiAddr)
		})
	},
}

var authLoginCmd = &cobra.Command{
	Use:   "login <username>",
	Short: "Log in and store an API key for this gateway",
	Long: "Prompts for the password, then mints an API key and saves it to\n" +
		"<data>/cli-credentials.json (0600) so later commands need no --api-key.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		pw, err := readPassword("password: ")
		if err != nil {
			return err
		}
		c := sdk()
		sess, err := c.Login(args[0], pw)
		if err != nil {
			return err
		}
		// Trade the session for an API key: sessions expire in hours, and the CLI
		// carries no state, so the key is what makes the next command work.
		created, err := c.CreateAPIKey(sess.User.ID, "cli@"+hostname(), 0)
		if err != nil {
			return fmt.Errorf("logged in, but minting an API key failed: %w", err)
		}
		return out(map[string]any{"user": sess.User, "key": created.Key}, func() {
			fmt.Printf("✓ logged in as %s (%s)\n\n", sess.User.Username, sess.User.Role)
			fmt.Printf("export TP_API_KEY=%s\n\n", created.Key)
			fmt.Printf("The key is shown only here. Revoke it with: trust-proxy apikey rm %s\n", created.ID)
		})
	},
}

var authWhoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show the account this CLI is authenticated as",
	RunE: func(cmd *cobra.Command, args []string) error {
		u, err := sdk().Me()
		if err != nil {
			return err
		}
		return out(u, func() {
			fmt.Printf("%-10s %s\n%-10s %s\n%-10s %v\n", "user:", u.Username, "role:", u.Role, "proxy:", u.HasProxyCred)
		})
	},
}

var authStateCmd = &cobra.Command{
	Use:   "state",
	Short: "Does this gateway need bootstrapping? Is registration open?",
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := sdk().AuthState()
		if err != nil {
			return err
		}
		return out(st, func() {
			fmt.Printf("%-16s %v\n", "needs bootstrap:", st.NeedsBootstrap)
			fmt.Printf("%-16s %v\n", "registration:", st.AllowRegistration)
			fmt.Printf("%-16s %v\n", "authenticated:", st.Authenticated)
			if st.User != nil {
				fmt.Printf("%-16s %s (%s)\n", "as:", st.User.Username, st.User.Role)
			}
		})
	},
}

var authRegisterCmd = &cobra.Command{
	Use:   "register <username>",
	Short: "Create your own account (only if an admin opened registration)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		pw, err := readNewPassword()
		if err != nil {
			return err
		}
		sess, err := sdk().Register(args[0], pw)
		if err != nil {
			return err
		}
		return out(sess, func() {
			fmt.Printf("✓ registered as %s (%s)\n\n  next:  trust-proxy auth login %s\n",
				sess.User.Username, sess.User.Role, sess.User.Username)
		})
	},
}

var authRegistrationCmd = &cobra.Command{
	Use:       "registration <on|off>",
	Short:     "Open or close self-registration (admin)",
	Args:      cobra.ExactArgs(1),
	ValidArgs: []string{"on", "off"},
	RunE: func(cmd *cobra.Command, args []string) error {
		on := strings.EqualFold(args[0], "on")
		if on {
			if err := confirm("Open self-registration? Anyone who can reach the console will be able to create an account"); err != nil {
				return err
			}
		}
		st, err := sdk().SetAuthSettings(apitypes.AuthSettings{AllowRegistration: on})
		if err != nil {
			return err
		}
		return out(st, func() {
			state := "closed"
			if st.AllowRegistration {
				state = "open"
			}
			fmt.Println("registration:", state)
		})
	},
}

// ---- user (local, on the file) -------------------------------------------

var (
	userAdmin    bool
	userRole     string
	userProxyPw  string
	userNoProxy  bool
	userPassword string
)

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage accounts (admin)",
	Long: "Goes through the API, like every other command: the gateway process is the\n" +
		"only writer of the account registry. Editing the file behind its back would\n" +
		"leave a running gateway with a stale copy — and it also means a proxy-password\n" +
		"change takes effect immediately instead of at the next restart.\n\n" +
		"Claiming a fresh gateway: run `auth bootstrap` on the machine itself (SSH means\n" +
		"loopback, which needs no credential). Lost every admin password: delete\n" +
		"<data>/users.json and the gateway goes back to unclaimed.",
}

var userLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List accounts",
	RunE: func(cmd *cobra.Command, args []string) error {
		list, err := sdk().Users()
		if err != nil {
			return err
		}
		return out(list, func() {
			if len(list) == 0 {
				fmt.Println("(no accounts yet — claim the gateway with `auth bootstrap <name>`)")
				return
			}
			fmt.Printf("%-14s %-16s %-7s %-9s %-6s %s\n", "ID", "USERNAME", "ROLE", "STATE", "PROXY", "KEYS")
			for _, u := range list {
				state := "enabled"
				if u.Disabled {
					state = "disabled"
				}
				fmt.Printf("%-14s %-16s %-7s %-9s %-6v %d\n", u.ID, truncate(u.Username, 16), u.Role, state, u.HasProxyCred, len(u.APIKeys))
			}
		})
	},
}

var userAddCmd = &cobra.Command{
	Use:   "add <username>",
	Short: "Create an account (the first one is always an admin)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		pw := userPassword
		var err error
		if pw == "" {
			if pw, err = readNewPassword(); err != nil {
				return err
			}
		}
		role := userRole
		if userAdmin {
			role = users.RoleAdmin
		}
		if role == "" {
			role = users.RoleClient
		}
		u, err := sdk().CreateUser(args[0], pw, role)
		if err != nil {
			return err
		}
		return out(u, func() {
			fmt.Printf("✓ created %s (%s)\n", u.Username, u.Role)
		})
	},
}

var userRmCmd = &cobra.Command{
	Use:   "rm <id|username>",
	Short: "Delete an account (never the last admin)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := resolveUser(args[0])
		if err != nil {
			return err
		}
		if err := sdk().DeleteUser(id); err != nil {
			return err
		}
		fmt.Println("✓ removed", args[0])
		return nil
	},
}

var userPasswdCmd = &cobra.Command{
	Use:   "passwd <id|username>",
	Short: "Set an account password",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := resolveUser(args[0])
		if err != nil {
			return err
		}
		pw := userPassword
		if pw == "" {
			if pw, err = readNewPassword(); err != nil {
				return err
			}
		}
		if _, err := sdk().PatchUser(id, apitypes.PatchUserRequest{Password: &pw}); err != nil {
			return err
		}
		fmt.Println("✓ password updated for", args[0])
		return nil
	},
}

var userRoleCmd = &cobra.Command{
	Use:   "role <id|username> <admin|user>",
	Short: "Change an account role",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := resolveUser(args[0])
		if err != nil {
			return err
		}
		if _, err := sdk().PatchUser(id, apitypes.PatchUserRequest{Role: &args[1]}); err != nil {
			return err
		}
		fmt.Printf("✓ %s is now %s\n", args[0], args[1])
		return nil
	},
}

var userDisableCmd = &cobra.Command{
	Use:   "disable <id|username>",
	Short: "Disable an account (use --enable to undo)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := resolveUser(args[0])
		if err != nil {
			return err
		}
		disabled := !userEnable
		if _, err := sdk().PatchUser(id, apitypes.PatchUserRequest{Disabled: &disabled}); err != nil {
			return err
		}
		fmt.Printf("✓ %s %s\n", args[0], map[bool]string{true: "disabled", false: "enabled"}[disabled])
		return nil
	},
}

var userEnable bool

var userProxyCmd = &cobra.Command{
	Use:   "proxy-pass <id|username>",
	Short: "Set this account's proxy-inbound password (--clear to revoke)",
	Long: "The proxy password is a *second* secret, separate from the login password:\n" +
		"sing-box checks it itself, so it has to be stored where it can be read, while\n" +
		"a login password only ever exists as a hash. The inbound username is the\n" +
		"account username. Any account with a proxy password can use the proxy port;\n" +
		"if nobody has one, the port stays open.\n\n" +
		"Takes effect immediately: the gateway re-derives the inbound's credential list\n" +
		"and hot-reloads it.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := resolveUser(args[0])
		if err != nil {
			return err
		}
		pw := userProxyPw
		if userNoProxy {
			pw = ""
		} else if pw == "" {
			if pw, err = readNewPassword(); err != nil {
				return err
			}
		}
		if _, err := sdk().PatchUser(id, apitypes.PatchUserRequest{ProxyPassword: &pw}); err != nil {
			return err
		}
		if pw == "" {
			fmt.Println("✓ proxy access revoked for", args[0])
		} else {
			fmt.Printf("✓ proxy password set for %s (username on the proxy: %s)\n", args[0], args[0])
		}
		return nil
	},
}

// ---- api keys (over the API) ---------------------------------------------

var (
	keyLabel string
	keyDays  int
	keyUser  string
)

var apikeyCmd = &cobra.Command{
	Use:   "apikey",
	Short: "API keys for non-interactive access",
}

var apikeyLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List the keys of an account (default: yourself)",
	RunE: func(cmd *cobra.Command, args []string) error {
		u, err := whoOrMe(keyUser)
		if err != nil {
			return err
		}
		return out(u.APIKeys, func() {
			if len(u.APIKeys) == 0 {
				fmt.Println("(no API keys)")
				return
			}
			fmt.Printf("%-14s %-22s %-12s %-22s %s\n", "ID", "LABEL", "PREFIX", "CREATED", "LAST USED")
			for _, k := range u.APIKeys {
				fmt.Printf("%-14s %-22s %-12s %-22s %s\n", k.ID, truncate(k.Label, 22), k.Prefix, k.CreatedAt, dash(k.LastUsedAt))
			}
		})
	},
}

var apikeyNewCmd = &cobra.Command{
	Use:   "new",
	Short: "Mint a key (shown once — only its hash is stored)",
	RunE: func(cmd *cobra.Command, args []string) error {
		u, err := whoOrMe(keyUser)
		if err != nil {
			return err
		}
		created, err := sdk().CreateAPIKey(u.ID, keyLabel, keyDays)
		if err != nil {
			return err
		}
		return out(created, func() {
			fmt.Printf("%s\n\nThis is the only time the key is shown; store it now.\n", created.Key)
		})
	},
}

var apikeyRmCmd = &cobra.Command{
	Use:   "rm <key-id>",
	Short: "Revoke a key",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		u, err := whoOrMe(keyUser)
		if err != nil {
			return err
		}
		if err := sdk().DeleteAPIKey(u.ID, args[0]); err != nil {
			return err
		}
		fmt.Println("✓ revoked", args[0])
		return nil
	},
}

// whoOrMe resolves --user (by id or username, admin only) or the caller.
func whoOrMe(who string) (apitypes.User, error) {
	if who == "" {
		return sdk().Me()
	}
	list, err := sdk().Users()
	if err != nil {
		return apitypes.User{}, err
	}
	for _, u := range list {
		if u.ID == who || strings.EqualFold(u.Username, who) {
			return u, nil
		}
	}
	return apitypes.User{}, fmt.Errorf("no such user %q", who)
}

// ---- helpers -------------------------------------------------------------

// resolveUser accepts an id or a username, so nobody has to copy ids around.
func resolveUser(ref string) (string, error) {
	list, err := sdk().Users()
	if err != nil {
		return "", err
	}
	for _, u := range list {
		if u.ID == ref || strings.EqualFold(u.Username, ref) {
			return u.ID, nil
		}
	}
	return "", fmt.Errorf("no such user %q", ref)
}

// readPassword reads without echoing. Falls back to a plain read when stdin is
// not a terminal, so scripts can pipe one in.
func readPassword(prompt string) (string, error) {
	if !term.IsTerminal(int(syscall.Stdin)) {
		var line string
		if _, err := fmt.Scanln(&line); err != nil {
			return "", fmt.Errorf("read password from stdin: %w", err)
		}
		return line, nil
	}
	fmt.Print(prompt)
	b, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// readNewPassword asks twice, so a typo does not become the password.
func readNewPassword() (string, error) {
	first, err := readPassword("new password: ")
	if err != nil {
		return "", err
	}
	if !term.IsTerminal(int(syscall.Stdin)) {
		return first, nil
	}
	again, err := readPassword("again: ")
	if err != nil {
		return "", err
	}
	if first != again {
		return "", fmt.Errorf("passwords do not match")
	}
	return first, nil
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "cli"
	}
	return h
}

func init() {
	authRegistrationCmd.Flags().BoolVarP(&yesToAll, "yes", "y", false, "skip the confirmation")
	authBootstrapCmd.Flags().StringVar(&authBootstrapCode, "code", "", "one-time bootstrap code (required off-loopback; printed in the gateway's log)")
	authCmd.AddCommand(authBootstrapCmd, authLoginCmd, authWhoamiCmd, authStateCmd, authRegisterCmd, authRegistrationCmd)

	userAddCmd.Flags().BoolVar(&userAdmin, "admin", false, "create an administrator")
	userAddCmd.Flags().StringVar(&userRole, "role", "", "role: admin | user (default user; the first account is always admin)")
	userAddCmd.Flags().StringVar(&userPassword, "password", "", "password (omit to be prompted; a flag lands in your shell history)")
	userPasswdCmd.Flags().StringVar(&userPassword, "password", "", "new password (omit to be prompted)")
	userDisableCmd.Flags().BoolVar(&userEnable, "enable", false, "enable instead of disable")
	userProxyCmd.Flags().StringVar(&userProxyPw, "password", "", "proxy password (omit to be prompted)")
	userProxyCmd.Flags().BoolVar(&userNoProxy, "clear", false, "revoke proxy access")
	userCmd.AddCommand(userLsCmd, userAddCmd, userRmCmd, userPasswdCmd, userRoleCmd, userDisableCmd, userProxyCmd)

	apikeyLsCmd.Flags().StringVar(&keyUser, "user", "", "another account, by id or username (admin only)")
	apikeyNewCmd.Flags().StringVar(&keyUser, "user", "", "another account, by id or username (admin only)")
	apikeyNewCmd.Flags().StringVar(&keyLabel, "label", "", "what this key is for")
	apikeyNewCmd.Flags().IntVar(&keyDays, "expires-in", 0, "expire after N days (0 = never)")
	apikeyRmCmd.Flags().StringVar(&keyUser, "user", "", "another account, by id or username (admin only)")
	apikeyCmd.AddCommand(apikeyLsCmd, apikeyNewCmd, apikeyRmCmd)
}
