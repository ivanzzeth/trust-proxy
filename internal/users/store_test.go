package users

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A fresh install has nobody, and whoever is created first must end up able to
// administer the gateway — otherwise the console is locked out of itself.
func TestFirstAccountIsAlwaysAdmin(t *testing.T) {
	s := newStore(t)
	if !s.Empty() {
		t.Fatal("a new registry must be empty (that is what triggers bootstrap)")
	}
	// Even asking for a plain user: the first one is promoted.
	u, err := s.Create("alice", "correct-horse-battery", RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	if u.Role != RoleAdmin {
		t.Fatalf("first account role = %q, want admin", u.Role)
	}
	if s.Empty() {
		t.Fatal("registry still reports empty after a create")
	}
	// The second one gets what it asked for.
	b, err := s.Create("bob", "another-long-password", RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	if b.Role != RoleUser {
		t.Fatalf("second account role = %q, want user", b.Role)
	}
}

func TestPasswordsAreHashedAndNeverStoredInTheClear(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	const pw = "a-very-long-password"
	if _, err := s.Create("alice", pw, RoleAdmin); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), pw) {
		t.Fatal("the password is on disk in the clear")
	}
	if !strings.Contains(string(raw), "$argon2id$") {
		t.Fatalf("expected an argon2id hash, got: %s", raw)
	}
	// The file holds hashes and proxy passwords: it must not be world-readable.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("users.json mode = %o, want 600", perm)
	}
}

func TestAuthenticate(t *testing.T) {
	s := newStore(t)
	if _, err := s.Create("alice", "correct-horse-battery", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate("alice", "correct-horse-battery"); err != nil {
		t.Fatalf("valid credentials rejected: %v", err)
	}
	// Case-insensitive username, exact password.
	if _, err := s.Authenticate("ALICE", "correct-horse-battery"); err != nil {
		t.Fatalf("username should be case-insensitive: %v", err)
	}
	if _, err := s.Authenticate("alice", "wrong"); err == nil {
		t.Fatal("a wrong password was accepted")
	}
	// A wrong name and a wrong password must be indistinguishable, or the error
	// tells an attacker which usernames exist.
	_, errUnknown := s.Authenticate("nobody", "correct-horse-battery")
	_, errWrongPw := s.Authenticate("alice", "not-the-password")
	if errUnknown == nil || errWrongPw == nil {
		t.Fatal("both should fail")
	}
	if errUnknown.Error() != errWrongPw.Error() {
		t.Fatalf("errors differ and leak whether the account exists: %q vs %q", errUnknown, errWrongPw)
	}
}

func TestDisabledAccountCannotAuthenticate(t *testing.T) {
	s := newStore(t)
	admin, _ := s.Create("admin", "correct-horse-battery", RoleAdmin)
	bob, _ := s.Create("bob", "another-long-password", RoleUser)
	if err := s.SetDisabled(bob.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate("bob", "another-long-password"); err == nil {
		t.Fatal("a disabled account authenticated")
	}
	// …and the last enabled admin cannot be disabled.
	if err := s.SetDisabled(admin.ID, true); err == nil {
		t.Fatal("disabling the last admin must be refused")
	}
}

// Locking yourself out is not a recoverable mistake on a remote gateway, so the
// store refuses the moves that would do it.
func TestLastAdminIsProtected(t *testing.T) {
	s := newStore(t)
	admin, _ := s.Create("admin", "correct-horse-battery", RoleAdmin)
	if err := s.SetRole(admin.ID, RoleUser); err == nil {
		t.Fatal("demoting the last admin must be refused")
	}
	if err := s.Delete(admin.ID); err == nil {
		t.Fatal("deleting the last admin must be refused")
	}
	// With a second admin, both become allowed.
	second, _ := s.Create("root2", "yet-another-password", RoleAdmin)
	if err := s.SetRole(admin.ID, RoleUser); err != nil {
		t.Fatalf("demotion with another admin present: %v", err)
	}
	if err := s.Delete(second.ID); err == nil {
		t.Fatal("second is now the last admin and must be protected")
	}
}

// One list of people: the proxy credential is *this account's* inbound password,
// keyed by the account username. It is a different secret from the login password
// because sing-box has to check it itself and therefore cannot take a hash.
func TestProxyPasswordIsThisAccountsSecondSecret(t *testing.T) {
	s := newStore(t)
	u, _ := s.Create("alice", "console-password-long", RoleAdmin)
	if err := s.SetProxyPassword(u.ID, "proxy-password"); err != nil {
		t.Fatal(err)
	}
	creds := s.ProxyCredentials()
	if len(creds) != 1 || creds[0].Username != "alice" || creds[0].Password != "proxy-password" {
		t.Fatalf("proxy credentials = %+v, want alice/proxy-password", creds)
	}
	// The login password is unaffected, and the proxy password is not a login one.
	if _, err := s.Authenticate("alice", "console-password-long"); err != nil {
		t.Fatalf("login broke: %v", err)
	}
	if _, err := s.Authenticate("alice", "proxy-password"); err == nil {
		t.Fatal("the proxy password must not authenticate to the console")
	}
	pub, _ := s.ByID(u.ID)
	if !pub.HasProxyCred {
		t.Fatalf("public view lost the proxy flag: %+v", pub)
	}
	// Clearing it removes inbound access.
	if err := s.SetProxyPassword(u.ID, ""); err != nil {
		t.Fatal(err)
	}
	if len(s.ProxyCredentials()) != 0 {
		t.Fatal("credential was not cleared")
	}
	// A disabled account must not keep proxy access either.
	bob, _ := s.Create("bob", "another-long-password", RoleUser)
	_ = s.SetProxyPassword(bob.ID, "bob-proxy-pass")
	_ = s.SetDisabled(bob.ID, true)
	if len(s.ProxyCredentials()) != 0 {
		t.Fatal("a disabled account still has inbound access")
	}
}

func TestAPIKeys(t *testing.T) {
	s := newStore(t)
	u, _ := s.Create("alice", "console-password-long", RoleAdmin)

	created, err := s.CreateAPIKey(u.ID, "cli@laptop", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.Key, KeyPrefix) {
		t.Fatalf("key %q lacks the %q prefix that makes a leak recognisable", created.Key, KeyPrefix)
	}
	got, err := s.AuthenticateAPIKey(created.Key)
	if err != nil {
		t.Fatalf("the key we just minted was rejected: %v", err)
	}
	if got.ID != u.ID || got.Role != RoleAdmin {
		t.Fatalf("key resolved to %+v", got)
	}
	if _, err := s.AuthenticateAPIKey(KeyPrefix + "not-a-real-key"); err == nil {
		t.Fatal("a bogus key was accepted")
	}
	// Only the hash is kept — the raw key must not be on disk anywhere.
	raw, _ := os.ReadFile(s.path)
	if strings.Contains(string(raw), created.Key) {
		t.Fatal("the raw API key is stored on disk")
	}
	// Revocation is immediate.
	if err := s.DeleteAPIKey(u.ID, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthenticateAPIKey(created.Key); err == nil {
		t.Fatal("a revoked key still authenticates")
	}
}

func TestAPIKeyExpiry(t *testing.T) {
	s := newStore(t)
	u, _ := s.Create("alice", "console-password-long", RoleAdmin)
	created, err := s.CreateAPIKey(u.ID, "short-lived", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthenticateAPIKey(created.Key); err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err := s.AuthenticateAPIKey(created.Key); err == nil {
		t.Fatal("an expired key still authenticates")
	}
}

func TestValidation(t *testing.T) {
	s := newStore(t)
	if _, err := s.Create("a", "long-enough-password", RoleAdmin); err == nil {
		t.Error("a one-character username should be refused")
	}
	if _, err := s.Create("bad name", "long-enough-password", RoleAdmin); err == nil {
		t.Error("a username with a space should be refused")
	}
	if _, err := s.Create("alice", "short", RoleAdmin); err == nil {
		t.Error("a 5-character password should be refused")
	}
	if _, err := s.Create("alice", "long-enough-password", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create("ALICE", "long-enough-password", RoleUser); err == nil {
		t.Error("usernames must be unique case-insensitively")
	}
}

// Reopening must see everything, and a bad file must not be silently treated as
// "no users" — that would put a live gateway back into bootstrap mode and let
// anyone claim the first admin account.
func TestPersistenceAndCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")
	s, _ := NewStore(path)
	u, _ := s.Create("alice", "console-password-long", RoleAdmin)
	key, _ := s.CreateAPIKey(u.ID, "cli", 0)

	again, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if again.Empty() {
		t.Fatal("reopened store lost its users")
	}
	if _, err := again.Authenticate("alice", "console-password-long"); err != nil {
		t.Fatalf("password did not survive a reopen: %v", err)
	}
	if _, err := again.AuthenticateAPIKey(key.Key); err != nil {
		t.Fatalf("API key did not survive a reopen: %v", err)
	}

	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(path); err == nil {
		t.Fatal("a corrupt users.json must be an error, not an empty registry")
	}
}

// Self-registration is off by default: an open signup form on a security gateway
// hands an account, and a view of the traffic, to anyone who can reach the port.
func TestRegistrationIsClosedByDefaultAndOnlyMakesPlainUsers(t *testing.T) {
	s := newStore(t)
	if s.Settings().AllowRegistration {
		t.Fatal("registration must default to closed")
	}
	// An empty registry is bootstrap territory — a stranger must not be able to
	// claim the first, admin, account through the registration path.
	if _, err := s.Register("stranger", "long-enough-password"); err == nil {
		t.Fatal("register on an empty registry must be refused")
	}
	if _, err := s.Create("admin", "console-password-long", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register("bob", "another-long-password"); err == nil {
		t.Fatal("registration is closed and must be refused")
	}

	if err := s.SetAllowRegistration(true); err != nil {
		t.Fatal(err)
	}
	bob, err := s.Register("bob", "another-long-password")
	if err != nil {
		t.Fatalf("registration should now succeed: %v", err)
	}
	if bob.Role != RoleUser {
		t.Fatalf("self-registered role = %q, want user (never admin)", bob.Role)
	}
	// The switch is persistent.
	again, err := NewStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Settings().AllowRegistration {
		t.Fatal("the registration setting did not survive a reopen")
	}
	if err := again.SetAllowRegistration(false); err != nil {
		t.Fatal(err)
	}
	if _, err := again.Register("carol", "yet-another-password"); err == nil {
		t.Fatal("closing registration must take effect immediately")
	}
}
