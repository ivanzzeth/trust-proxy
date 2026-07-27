package cmd

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/ivanzzeth/trust-proxy/internal/credentials"
	"github.com/ivanzzeth/trust-proxy/internal/users"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
	"github.com/ivanzzeth/trust-proxy/pkg/client"
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
	// A named error beats cobra's "accepts 1 arg(s), received 0": the username is
	// the account you will log in with forever, and the docs shipped without it
	// once already.
	Args: func(_ *cobra.Command, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("choose a username for the first admin, e.g. `trust-proxy auth bootstrap admin`" +
				" (the password is asked for next; it is not a flag)")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		pw, err := readNewPassword()
		if err != nil {
			return err
		}
		sess, err := loginSDK().Bootstrap(args[0], pw, authBootstrapCode)
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
	Short: "Log in and save an API key for this gateway",
	Long: "Prompts for the password, then trades the session for an API key and saves it\n" +
		"for this gateway's address. Later commands need no flag and no environment\n" +
		"variable.\n\n" +
		"The key replaces this machine's previous one rather than piling up beside it:\n" +
		"logging in five times used to leave five live keys on the account, all named\n" +
		"the same, none of them removable without reading their ids.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		pw, err := readPassword("password: ")
		if err != nil {
			return err
		}
		c := loginSDK()
		sess, err := c.Login(args[0], pw)
		if err != nil {
			return err
		}
		label := "cli@" + hostname()
		// Rotate this machine's stored key rather than piling another one beside it.
		// A session expires in hours and the CLI carries no session, so every login
		// has to mint a key; without this the account collects one per login,
		// forever, all with the same label.
		//
		// Only the key this machine had *stored* is revoked — not every key sharing
		// the label. Someone who exported a key into a script keeps it; taking that
		// out from under them because they logged in again would be a worse bug than
		// the one being fixed.
		revokeStoredKey(c)
		created, err := c.CreateAPIKey(sess.User.ID, label, 0)
		if err != nil {
			return fmt.Errorf("logged in, but minting an API key failed: %w", err)
		}
		// The gateway id goes in with the key so a later 401 can distinguish "this
		// gateway was reinstalled" from "your key was revoked".
		var gatewayID string
		if st, err := c.AuthState(); err == nil {
			gatewayID = st.GatewayID
		}
		path, saveErr := rememberCredential(credentials.Entry{
			GatewayID: gatewayID,
			Key:       created.Key,
			KeyID:     created.ID,
			UserID:    sess.User.ID,
			Username:  sess.User.Username,
		})
		return out(map[string]any{"user": sess.User, "key": created.Key, "credentials_path": path}, func() {
			fmt.Printf("✓ logged in as %s (%s)\n", sess.User.Username, sess.User.Role)
			if saveErr != nil {
				// Do not swallow it: the key is only shown once, and a user who
				// believes it was saved has just lost it.
				fmt.Printf("\n⚠ could not save the key (%v). Use it by hand:\n\n", saveErr)
				fmt.Printf("    export TP_API_KEY=%s\n", created.Key)
				return
			}
			fmt.Printf("  saved to %s — the CLI will use it automatically.\n", path)
			fmt.Printf("  revoke it with: trust-proxy apikey rm %s\n", created.ID)
		})
	},
}

// revokeStoredKey retires the key this machine had saved for this gateway.
//
// Best effort on purpose: the stored key may already be gone, or belong to
// another account this session cannot administer, and neither should turn a
// successful login into a failure. The worst case is the old behaviour — one
// spare key left behind.
func revokeStoredKey(c *client.Client) {
	old, ok := storedCredential()
	if !ok || old.KeyID == "" || old.UserID == "" {
		return
	}
	_ = c.DeleteAPIKey(old.UserID, old.KeyID)
}

var authTicketCmd = &cobra.Command{
	Use:   "ticket",
	Short: "Mint a one-time URL that opens the console already logged in",
	Long: "Turns the API key this CLI already holds into a single-use link. Following it\n" +
		"sets a session cookie and lands on the console.\n\n" +
		"This is how the desktop app opens the console: it holds a key (the one\n" +
		"`install` wrote into your home directory) but a web view needs a *cookie*, and\n" +
		"only the gateway's own origin can set one. Handing the key to the page instead\n" +
		"would leave an admin credential sitting inside a web view. The ticket is good\n" +
		"for one redirect and one minute.",
	RunE: func(cmd *cobra.Command, args []string) error {
		t, err := sdk().ConsoleTicket()
		if err != nil {
			return err
		}
		return out(t, func() { fmt.Println(t.URL) })
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
	userAdmin           bool
	userRole            string
	userProxyPw         string
	userNoProxy         bool
	userPassword        string
	userCurrentPassword string
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
		req := apitypes.PatchUserRequest{Password: &pw}
		if userCurrentPassword != "" {
			req.CurrentPassword = &userCurrentPassword
		}
		_, err = sdk().PatchUser(id, req)
		// Changing your *own* password needs the current one — an admin resetting
		// somebody else's does not, and cannot, so the requirement is not knowable
		// from here without another round trip. Ask for it when the API says so
		// rather than asking every time or guessing which case this is.
		if err != nil && strings.Contains(err.Error(), "requires current_password") && userCurrentPassword == "" {
			cur, perr := readPassword("current password: ")
			if perr != nil {
				return perr
			}
			req.CurrentPassword = &cur
			_, err = sdk().PatchUser(id, req)
		}
		if err != nil {
			return err
		}
		fmt.Println("✓ password updated for", args[0])
		// The old sessions are gone, and so is the API key the CLI was using if it
		// belonged to a session rather than a key — worth saying, because "why did my
		// other terminal stop working" is otherwise a mystery.
		fmt.Println("  every session that password opened has ended; API keys are unaffected")
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
	authCmd.AddCommand(authBootstrapCmd, authLoginCmd, authTicketCmd, authWhoamiCmd,
		authStateCmd, authRegisterCmd, authRegistrationCmd)

	userAddCmd.Flags().BoolVar(&userAdmin, "admin", false, "create an administrator")
	userAddCmd.Flags().StringVar(&userRole, "role", "", "role: admin | user (default user; the first account is always admin)")
	userAddCmd.Flags().StringVar(&userPassword, "password", "", "password (omit to be prompted; a flag lands in your shell history)")
	userPasswdCmd.Flags().StringVar(&userCurrentPassword, "current", "",
		"your current password, required when changing your own (omit to be prompted)")
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

	requestAskCmd.Flags().StringVar(&requestReason, "reason", "", "why you need it (shown to the admin)")
	requestCmd.AddCommand(requestAskCmd, requestLsCmd, requestApproveCmd, requestDenyCmd)
}

// ---- permit requests -----------------------------------------------------

// `request` is how a client asks for something the gateway denies. It cannot
// widen policy itself — a local rule would be silently ineffective, since the
// traffic still meets the gateway's default-deny — so asking is the honest path.

var requestCmd = &cobra.Command{
	Use:   "request",
	Short: "Ask an admin to permit a destination (or, as admin, review requests)",
}

var requestReason string

var requestAskCmd = &cobra.Command{
	Use:   "ask <host>",
	Short: "Ask for a destination to be permitted",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		res, err := sdk().RequestPermit(args[0], requestReason)
		if err != nil {
			return err
		}
		return out(res, func() {
			fmt.Printf("✓ requested %s — pending an administrator's approval\n", args[0])
		})
	},
}

var requestLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List pending requests (yours, or everyone's if you are an admin)",
	RunE: func(cmd *cobra.Command, args []string) error {
		reqs, err := sdk().PermitRequests()
		if err != nil {
			return err
		}
		return out(reqs, func() {
			if len(reqs) == 0 {
				fmt.Println("(no pending requests)")
				return
			}
			fmt.Printf("%-14s %-30s %-18s %-8s %s\n", "ID", "HOST", "ASKED BY", "STATE", "REASON")
			for _, r := range reqs {
				state := "pending"
				if r.Enabled {
					state = "approved"
				}
				fmt.Printf("%-14s %-30s %-18s %-8s %s\n",
					r.ID, truncate(r.Value, 30), strings.TrimPrefix(r.Pack, apitypes.PackRequestPrefix),
					state, truncate(r.Note, 40))
			}
		})
	},
}

var requestApproveCmd = &cobra.Command{
	Use:   "approve <id>",
	Short: "Permit what was asked for (admin)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		rules, err := sdk().ApprovePermitRequest(args[0])
		if err != nil {
			return err
		}
		return out(rules, func() { fmt.Println("✓ approved; the rule is now in force") })
	},
}

var requestDenyCmd = &cobra.Command{
	Use:   "deny <id>",
	Short: "Discard a request (admin)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		rules, err := sdk().DenyPermitRequest(args[0])
		if err != nil {
			return err
		}
		return out(rules, func() { fmt.Println("✓ discarded") })
	},
}
