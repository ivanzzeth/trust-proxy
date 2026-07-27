// Package credentials stores the API key the CLI uses to talk to a gateway.
//
// This is the only thing this project puts in a home directory. It is a secret,
// not state: the gateway never reads it, and losing it costs one `trust-proxy
// auth login`, not any policy.
//
// There was a credentials file once before and it was deleted, because it went
// stale against a rebuilt registry and then turned a perfectly healthy gateway
// into a 401 nobody could explain. The answer to a stale credential is to notice
// it is stale, not to have no credential and make every user paste
// `eval "$(… | grep ^export)"` into their shell forever. So every entry carries
// the **gateway id** it was minted against; when that does not match, the entry
// is discarded with a sentence saying why.
package credentials

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ivanzzeth/trust-proxy/internal/paths"
)

// Entry is one gateway's credential.
type Entry struct {
	// GatewayID identifies the registry this key belongs to. A gateway that was
	// reinstalled, or whose users.json was deleted, reports a different one — and
	// that is exactly when a cached key becomes a confusing 401.
	GatewayID string `json:"gateway_id"`
	Key       string `json:"key"`
	// KeyID identifies the key server-side, so logging in again can revoke exactly
	// the one it is replacing. Without it the only handle is the label, and
	// revoking by label takes out every key this machine ever minted — including
	// one somebody deliberately exported into a script.
	KeyID     string `json:"key_id,omitempty"`
	UserID    string `json:"user_id,omitempty"`
	Username  string `json:"username,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// File is the on-disk shape: one entry per gateway address, because one laptop
// legitimately talks to its own gateway and to remote ones.
type File struct {
	Gateways map[string]Entry `json:"gateways"`
}

// Path is the credentials file for this process's user.
func Path() (string, error) { return paths.CredentialsFile() }

// Load reads the file. A missing file is not an error — it is the normal state
// before the first login.
func Load(path string) (File, error) {
	f := File{Gateways: map[string]Entry{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return File{Gateways: map[string]Entry{}}, fmt.Errorf("parse %s: %w", path, err)
	}
	if f.Gateways == nil {
		f.Gateways = map[string]Entry{}
	}
	return f, nil
}

// Get returns the credential for an address, if there is one.
func Get(path, addr string) (Entry, bool) {
	f, err := Load(path)
	if err != nil {
		return Entry{}, false
	}
	e, ok := f.Gateways[key(addr)]
	return e, ok && e.Key != ""
}

// Put records a credential, replacing whatever was there for that address.
func Put(path, addr string, e Entry) error {
	f, err := Load(path)
	if err != nil {
		// A corrupt file must not block logging in again — that would make the
		// recovery path depend on the thing that is broken.
		f = File{Gateways: map[string]Entry{}}
	}
	e.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	f.Gateways[key(addr)] = e
	return write(path, f, nil)
}

// Forget drops the credential for an address (a stale one, or a logout).
func Forget(path, addr string) error {
	f, err := Load(path)
	if err != nil {
		return err
	}
	delete(f.Gateways, key(addr))
	return write(path, f, nil)
}

// PutFor writes a credential into somebody else's home and hands them the file.
//
// This is the `install` path: the command runs as root, and the person who
// authorized it must end up owning the key — a 0600 file owned by root in their
// home is the same as no key at all. Every directory this creates is chowned too,
// or the next `auth login` as that user cannot rewrite the file it just read.
func PutFor(owner paths.Owner, addr string, e Entry) (string, error) {
	path := paths.CredentialsFileFor(owner.Home)
	f, err := Load(path)
	if err != nil {
		f = File{Gateways: map[string]Entry{}}
	}
	e.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	f.Gateways[key(addr)] = e
	if err := write(path, f, &owner); err != nil {
		return "", err
	}
	return path, nil
}

// write persists the file 0600, creating the directory chain, and (when owner is
// set) transferring ownership of everything it had to create.
func write(path string, f File, owner *paths.Owner) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := mkdirChain(filepath.Dir(path), owner); err != nil {
		return err
	}
	// Write-then-rename: a half-written credentials file reads as a corrupt one,
	// and the recovery for that is another login nobody expected to need.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := chown(tmp, owner); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// mkdirChain creates dir and every missing parent, chowning only what it
// actually created — an existing ~/.config belongs to the user already, and
// re-chowning somebody's whole config directory is not ours to do.
func mkdirChain(dir string, owner *paths.Owner) error {
	if _, err := os.Stat(dir); err == nil {
		return nil
	}
	parent := filepath.Dir(dir)
	if parent != dir {
		if err := mkdirChain(parent, owner); err != nil {
			return err
		}
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !os.IsExist(err) {
		return err
	}
	return chown(dir, owner)
}

func chown(path string, owner *paths.Owner) error {
	if owner == nil || owner.UID < 0 || owner.GID < 0 {
		return nil // not applicable (Windows), or writing as ourselves
	}
	if err := os.Chown(path, owner.UID, owner.GID); err != nil {
		return fmt.Errorf("hand %s to %s: %w", path, owner.Username, err)
	}
	return nil
}

func key(addr string) string { return strings.ToLower(strings.TrimSpace(addr)) }
