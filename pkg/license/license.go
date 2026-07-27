// Package license defines the on-disk license format used by interpose
// and helpers for signing (backend) and verifying (CLI). The license is
// a small JSON blob plus an Ed25519 signature. Verification is offline:
// the CLI bakes the public key in at build time and checks the signature
// locally — no network calls happen at runtime.
package license

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// SchemaVersion is the version of the License JSON schema this package
// understands. Verify rejects licenses with an unknown schema_version so
// older CLIs don't silently accept newer formats.
const SchemaVersion = 1

// Tier identifies what the buyer paid for.
type Tier string

const (
	// Free: the register-only, never-expiring tier. Unlocks the Instant/nono
	// kernel sandbox only; governance, Sealed/Ambient, and teams are upgrades.
	TierFree Tier = "free"

	TierTrial    Tier = "trial"
	TierAcademic Tier = "academic"
	TierYearly   Tier = "yearly"
	TierForever  Tier = "forever"
)

// License is the inner, signed payload.
type License struct {
	SchemaVersion int        `json:"schema_version"`
	LicenseID     string     `json:"license_id"`
	Email         string     `json:"email"`
	Tier          Tier       `json:"tier"`
	IssuedAt      time.Time  `json:"issued_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	DevicePubkey  []byte     `json:"device_pubkey"`
	Products      []string   `json:"products"`
}

// Signed wraps a License with the Ed25519 signature computed over its
// canonical encoding.
type Signed struct {
	License   License `json:"license"`
	Signature []byte  `json:"signature"`
}

// Canonical returns the deterministic JSON encoding of l used as the
// signing/verification input. Times are normalized to UTC at second
// precision so values differing only in timezone or sub-second precision
// produce identical bytes.
func (l License) Canonical() ([]byte, error) {
	return json.Marshal(l.normalized())
}

func (l License) normalized() License {
	n := l
	n.IssuedAt = n.IssuedAt.UTC().Truncate(time.Second)
	if n.ExpiresAt != nil {
		t := n.ExpiresAt.UTC().Truncate(time.Second)
		n.ExpiresAt = &t
	}
	return n
}

// Sign returns a Signed envelope wrapping lic. The envelope contains the
// normalized form of lic so the on-disk representation matches exactly
// what was signed.
func Sign(lic License, priv ed25519.PrivateKey) (*Signed, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("license: private key wrong size: got %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	norm := lic.normalized()
	payload, err := json.Marshal(norm)
	if err != nil {
		return nil, fmt.Errorf("license: encode: %w", err)
	}
	return &Signed{
		License:   norm,
		Signature: ed25519.Sign(priv, payload),
	}, nil
}

// Verify checks s.Signature against s.License using pub. Returns nil on
// a valid signature with a recognized schema version.
func Verify(s *Signed, pub ed25519.PublicKey) error {
	if s == nil {
		return errors.New("license: nil Signed")
	}
	if s.License.SchemaVersion != SchemaVersion {
		return fmt.Errorf("license: unknown schema_version %d (want %d)", s.License.SchemaVersion, SchemaVersion)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("license: public key wrong size: got %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	payload, err := s.License.Canonical()
	if err != nil {
		return fmt.Errorf("license: encode: %w", err)
	}
	if !ed25519.Verify(pub, payload, s.Signature) {
		return errors.New("license: signature invalid")
	}
	return nil
}

// IsExpired reports whether l.ExpiresAt is set and before now.
// Forever licenses (ExpiresAt == nil) never expire.
func (l License) IsExpired(now time.Time) bool {
	if l.ExpiresAt == nil {
		return false
	}
	return l.ExpiresAt.Before(now)
}

// IsForever reports whether l has no expiry date.
func (l License) IsForever() bool {
	return l.ExpiresAt == nil
}
