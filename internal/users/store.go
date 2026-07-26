// Package users persists console accounts, their roles, and their API keys.
//
// Why this exists: once the data plane runs as a privileged system service, an
// unauthenticated loopback API is a privilege-escalation surface — any
// unprivileged local process could switch off default-deny, and letting itself
// out is exactly what an implant wants. So the API gets identities.
//
// Two passwords per person, and they cannot be the same secret:
//
//   - the **account password** authenticates a human to the console. It is stored
//     as an argon2id hash and is never recoverable.
//   - the **proxy password** authenticates a client of that same person to the
//     mixed inbound. sing-box validates it itself, so it has to go into the
//     generated config in the clear; a hash would be useless there. The inbound
//     username is the account username — one list of people, not two.
//
// Conflating them would mean either storing the account password reversibly
// (bad) or handing sing-box a hash it cannot check (broken). They are separate
// fields on purpose.
package users

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Roles. Admin may change policy, mode, users and fleet; User is read-only on
// the observability surface (connections, history, detections, status).
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

// KeyPrefix marks our API keys so a leaked one is recognisable in a log.
const KeyPrefix = "tp_"

// argon2id parameters: OWASP's low-memory profile (19 MiB, t=2, p=1). Chosen so a
// login stays sub-100ms on a Raspberry Pi — this project is meant to run on one —
// while keeping the memory hardness that makes GPU cracking expensive.
const (
	argonTime    = 2
	argonMemory  = 19 * 1024 // KiB
	argonThreads = 1
	argonKeyLen  = 32
	saltLen      = 16
)

// User is one account. PasswordHash is argon2id; ProxyPassword is plaintext
// because sing-box has to check it (see the package comment).
type User struct {
	ID            string   `json:"id"`
	Username      string   `json:"username"`
	PasswordHash  string   `json:"password_hash"`
	Role          string   `json:"role"`
	Disabled      bool     `json:"disabled,omitempty"`
	ProxyPassword string   `json:"proxy_password,omitempty"` // plaintext, unavoidably (see above)
	APIKeys       []APIKey `json:"api_keys,omitempty"`
	CreatedAt     string   `json:"created_at"`
	LastLoginAt   string   `json:"last_login_at,omitempty"`
}

// APIKey is a non-interactive credential, for the CLI and for scripts.
//
// Only the sha256 of the key is kept. That is enough here — unlike a human
// password, the key is 32 random bytes, so there is no dictionary to run and no
// reason to pay argon2's cost on every request.
type APIKey struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Prefix     string `json:"prefix"` // first 10 chars, for display
	Hash       string `json:"hash"`   // sha256 hex of the whole key
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}

// Store is a file-backed user registry, safe for concurrent use.
type Store struct {
	path string
	mu   sync.Mutex
	data doc
	now  func() time.Time
}

type doc struct {
	Users    []User   `json:"users"`
	Settings Settings `json:"settings"`
}

// Settings are the registry-wide knobs an admin can flip at runtime.
type Settings struct {
	// AllowRegistration lets strangers create their own (non-admin) account.
	// Default false, and deliberately so: this is a security gateway, and an open
	// signup form on it means anyone who can reach the console gets an account and
	// a look at the traffic. The first admin is created by bootstrap, not by
	// registration, so nothing depends on this being on.
	AllowRegistration bool `json:"allow_registration"`
}

// NewStore opens (or creates) the registry. The file holds password hashes and
// proxy passwords, so it is 0600 — not the 0644 the other stores use.
func NewStore(path string) (*Store, error) {
	s := &Store{path: path, now: time.Now}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil // empty registry = needs bootstrap
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.data); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return s, nil
}

func (s *Store) save() error {
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	// Write-then-rename with 0600: a truncated user file would lock everyone out.
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Empty reports whether anybody has been created yet. An empty registry is what
// puts the API in bootstrap mode.
func (s *Store) Empty() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.data.Users) == 0
}

// Settings returns the registry-wide knobs.
func (s *Store) Settings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Settings
}

// SetAllowRegistration opens or closes self-registration (admin only, upstream).
func (s *Store) SetAllowRegistration(allow bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Settings.AllowRegistration = allow
	return s.save()
}

// Register is self-signup: it creates a plain user, never an admin, and only when
// an admin has opened registration.
//
// An empty registry is bootstrap, not registration — routing it here would let a
// stranger claim the first (admin) account on a gateway whose owner had not
// finished setting it up.
func (s *Store) Register(username, password string) (apitypes.User, error) {
	s.mu.Lock()
	empty := len(s.data.Users) == 0
	allow := s.data.Settings.AllowRegistration
	s.mu.Unlock()
	if empty {
		return apitypes.User{}, fmt.Errorf("no accounts yet: create the first admin instead (bootstrap)")
	}
	if !allow {
		return apitypes.User{}, ErrRegistrationClosed
	}
	return s.Create(username, password, RoleUser)
}

// ErrRegistrationClosed is returned when self-signup is off (the default).
var ErrRegistrationClosed = fmt.Errorf("registration is closed: ask an administrator to create your account")

// List returns every account, with secrets stripped.
func (s *Store) List() []apitypes.User {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]apitypes.User, 0, len(s.data.Users))
	for _, u := range s.data.Users {
		out = append(out, u.public())
	}
	return out
}

// Create adds an account. The first account created is always an admin —
// otherwise a fresh install would have a console nobody can administer.
func (s *Store) Create(username, password, role string) (apitypes.User, error) {
	if err := validUsername(username); err != nil {
		return apitypes.User{}, err
	}
	if err := validPassword(password); err != nil {
		return apitypes.User{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.findLocked(username) != nil {
		return apitypes.User{}, fmt.Errorf("user %q already exists", username)
	}
	if len(s.data.Users) == 0 {
		role = RoleAdmin
	} else if role != RoleAdmin && role != RoleUser {
		return apitypes.User{}, fmt.Errorf("role must be %s or %s", RoleAdmin, RoleUser)
	}
	hash, err := HashPassword(password)
	if err != nil {
		return apitypes.User{}, err
	}
	u := User{
		ID:           newID(),
		Username:     username,
		PasswordHash: hash,
		Role:         role,
		CreatedAt:    s.now().UTC().Format(time.RFC3339),
	}
	s.data.Users = append(s.data.Users, u)
	if err := s.save(); err != nil {
		s.data.Users = s.data.Users[:len(s.data.Users)-1]
		return apitypes.User{}, err
	}
	return u.public(), nil
}

// Authenticate checks a username/password pair and returns the account.
func (s *Store) Authenticate(username, password string) (apitypes.User, error) {
	s.mu.Lock()
	u := s.findLocked(username)
	var hash string
	if u != nil {
		hash = u.PasswordHash
	}
	s.mu.Unlock()

	// Verify outside the lock (argon2id is deliberately slow — holding the mutex
	// would serialise every other reader behind a login attempt), and verify even
	// when the user is unknown so a wrong name and a wrong password cost the same.
	ok := VerifyPassword(hash, password)
	if u == nil || !ok {
		return apitypes.User{}, ErrInvalidCredentials
	}
	if u.Disabled {
		return apitypes.User{}, fmt.Errorf("account is disabled")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if live := s.findLocked(username); live != nil {
		live.LastLoginAt = s.now().UTC().Format(time.RFC3339)
		_ = s.save()
		return live.public(), nil
	}
	return u.public(), nil
}

// ErrInvalidCredentials is returned for both a wrong username and a wrong
// password: telling them apart is an account-enumeration oracle.
var ErrInvalidCredentials = fmt.Errorf("invalid username or password")

// SetPassword changes an account password.
func (s *Store) SetPassword(id, password string) error {
	if err := validPassword(password); err != nil {
		return err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	return s.mutate(id, func(u *User) error {
		u.PasswordHash = hash
		return nil
	})
}

// SetRole changes an account role, refusing to remove the last admin.
func (s *Store) SetRole(id, role string) error {
	if role != RoleAdmin && role != RoleUser {
		return fmt.Errorf("role must be %s or %s", RoleAdmin, RoleUser)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.byIDLocked(id)
	if u == nil {
		return fmt.Errorf("no such user")
	}
	if u.Role == RoleAdmin && role != RoleAdmin && s.adminCountLocked() == 1 {
		return fmt.Errorf("refusing to demote the last admin: nobody could administer the gateway")
	}
	u.Role = role
	return s.save()
}

// SetDisabled enables or disables an account, refusing to disable the last admin.
func (s *Store) SetDisabled(id string, disabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.byIDLocked(id)
	if u == nil {
		return fmt.Errorf("no such user")
	}
	if disabled && u.Role == RoleAdmin && s.enabledAdminCountLocked() == 1 {
		return fmt.Errorf("refusing to disable the last enabled admin")
	}
	u.Disabled = disabled
	return s.save()
}

// SetProxyPassword gives this account access to the proxy inbound, or takes it
// away (empty string). The inbound username is the account username.
//
// This is *not* the login password — see the package comment for why they cannot
// be the same secret.
func (s *Store) SetProxyPassword(id, password string) error {
	if password != "" && len(password) < 8 {
		return fmt.Errorf("proxy password must be at least 8 characters")
	}
	return s.mutate(id, func(u *User) error {
		u.ProxyPassword = password
		return nil
	})
}

// ProxyCredentials returns every enabled account that has a proxy password, for
// injection into the sing-box mixed inbound. Empty result = the inbound stays
// open (sing-box requires auth only when a users list is present).
func (s *Store) ProxyCredentials() []apitypes.ProxyCredential {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []apitypes.ProxyCredential
	for _, u := range s.data.Users {
		if u.Disabled || u.ProxyPassword == "" {
			continue
		}
		out = append(out, apitypes.ProxyCredential{Username: u.Username, Password: u.ProxyPassword})
	}
	return out
}

// Delete removes an account, refusing to remove the last admin.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, u := range s.data.Users {
		if u.ID != id {
			continue
		}
		if u.Role == RoleAdmin && s.adminCountLocked() == 1 {
			return fmt.Errorf("refusing to delete the last admin")
		}
		s.data.Users = append(s.data.Users[:i], s.data.Users[i+1:]...)
		return s.save()
	}
	return fmt.Errorf("no such user")
}

// ---- API keys ------------------------------------------------------------

// CreateAPIKey mints a key for an account and returns it **once** — only its
// hash is stored, so a lost key cannot be recovered, only replaced.
func (s *Store) CreateAPIKey(userID, label string, ttl time.Duration) (apitypes.APIKeyCreated, error) {
	raw := KeyPrefix + randomToken(32)
	key := APIKey{
		ID:        newID(),
		Label:     strings.TrimSpace(label),
		Prefix:    raw[:min(10, len(raw))],
		Hash:      hashKey(raw),
		CreatedAt: s.now().UTC().Format(time.RFC3339),
	}
	if ttl > 0 {
		key.ExpiresAt = s.now().Add(ttl).UTC().Format(time.RFC3339)
	}
	if err := s.mutate(userID, func(u *User) error {
		u.APIKeys = append(u.APIKeys, key)
		return nil
	}); err != nil {
		return apitypes.APIKeyCreated{}, err
	}
	return apitypes.APIKeyCreated{APIKey: key.public(), Key: raw}, nil
}

// DeleteAPIKey revokes one key.
func (s *Store) DeleteAPIKey(userID, keyID string) error {
	return s.mutate(userID, func(u *User) error {
		for i, k := range u.APIKeys {
			if k.ID == keyID {
				u.APIKeys = append(u.APIKeys[:i], u.APIKeys[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("no such API key")
	})
}

// AuthenticateAPIKey resolves a raw key to its account, refusing disabled
// accounts and expired keys, and records last use.
func (s *Store) AuthenticateAPIKey(raw string) (apitypes.User, error) {
	if !strings.HasPrefix(raw, KeyPrefix) {
		return apitypes.User{}, ErrInvalidCredentials
	}
	want := hashKey(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Users {
		u := &s.data.Users[i]
		for j := range u.APIKeys {
			k := &u.APIKeys[j]
			// Constant-time compare: the hashes are not secret, but this costs
			// nothing and keeps timing out of the story entirely.
			if subtle.ConstantTimeCompare([]byte(k.Hash), []byte(want)) != 1 {
				continue
			}
			if u.Disabled {
				return apitypes.User{}, fmt.Errorf("account is disabled")
			}
			if k.ExpiresAt != "" {
				if exp, err := time.Parse(time.RFC3339, k.ExpiresAt); err == nil && s.now().After(exp) {
					return apitypes.User{}, fmt.Errorf("API key expired")
				}
			}
			k.LastUsedAt = s.now().UTC().Format(time.RFC3339)
			_ = s.save()
			return u.public(), nil
		}
	}
	return apitypes.User{}, ErrInvalidCredentials
}

// ByID returns one account with secrets stripped.
func (s *Store) ByID(id string) (apitypes.User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u := s.byIDLocked(id); u != nil {
		return u.public(), true
	}
	return apitypes.User{}, false
}

// ---- password hashing ----------------------------------------------------

// HashPassword returns a PHC-style argon2id string.
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks a password against a stored hash. An unparsable or empty
// hash still costs one derivation, so an unknown account and a wrong password
// take the same time.
func VerifyPassword(stored, password string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		_ = argon2.IDKey([]byte(password), make([]byte, saltLen), argonTime, argonMemory, argonThreads, argonKeyLen)
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// ---- helpers -------------------------------------------------------------

func (s *Store) mutate(id string, f func(*User) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.byIDLocked(id)
	if u == nil {
		return fmt.Errorf("no such user")
	}
	if err := f(u); err != nil {
		return err
	}
	return s.save()
}

func (s *Store) findLocked(username string) *User {
	for i := range s.data.Users {
		if strings.EqualFold(s.data.Users[i].Username, username) {
			return &s.data.Users[i]
		}
	}
	return nil
}

func (s *Store) byIDLocked(id string) *User {
	for i := range s.data.Users {
		if s.data.Users[i].ID == id {
			return &s.data.Users[i]
		}
	}
	return nil
}

func (s *Store) adminCountLocked() int {
	n := 0
	for _, u := range s.data.Users {
		if u.Role == RoleAdmin {
			n++
		}
	}
	return n
}

func (s *Store) enabledAdminCountLocked() int {
	n := 0
	for _, u := range s.data.Users {
		if u.Role == RoleAdmin && !u.Disabled {
			n++
		}
	}
	return n
}

func (u User) public() apitypes.User {
	keys := make([]apitypes.APIKey, 0, len(u.APIKeys))
	for _, k := range u.APIKeys {
		keys = append(keys, k.public())
	}
	return apitypes.User{
		ID: u.ID, Username: u.Username, Role: u.Role, Disabled: u.Disabled,
		// Whether this person can use the proxy is worth showing; the password
		// itself never leaves the server.
		HasProxyCred: u.ProxyPassword != "",
		APIKeys:      keys,
		CreatedAt:    u.CreatedAt,
		LastLoginAt:  u.LastLoginAt,
	}
}

func (k APIKey) public() apitypes.APIKey {
	return apitypes.APIKey{
		ID: k.ID, Label: k.Label, Prefix: k.Prefix,
		CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt, ExpiresAt: k.ExpiresAt,
	}
}

func validUsername(name string) error {
	name = strings.TrimSpace(name)
	if len(name) < 2 || len(name) > 32 {
		return fmt.Errorf("username must be 2-32 characters")
	}
	for _, r := range name {
		if !(r == '-' || r == '_' || r == '.' || r == '@' ||
			(r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return fmt.Errorf("username may only contain letters, digits and - _ . @")
		}
	}
	return nil
}

// validPassword sets a floor, not a policy: length beats composition rules, and
// arbitrary character classes just push people to Passw0rd!.
func validPassword(p string) error {
	if len(p) < 10 {
		return fmt.Errorf("password must be at least 10 characters")
	}
	if len(p) > 256 {
		return fmt.Errorf("password must be at most 256 characters")
	}
	return nil
}

func hashKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func newID() string {
	return randomToken(9)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
