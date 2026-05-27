package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

func mustGenKey(tb testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	tb.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}

func newTestLicense(devicePub ed25519.PublicKey) License {
	expires := time.Date(2027, 5, 27, 12, 0, 0, 0, time.UTC)
	return License{
		SchemaVersion: SchemaVersion,
		LicenseID:     "550e8400-e29b-41d4-a716-446655440000",
		Email:         "alice@example.com",
		Tier:          TierYearly,
		IssuedAt:      time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC),
		ExpiresAt:     &expires,
		DevicePubkey:  devicePub,
		Products:      []string{"interpose"},
	}
}

func TestSignVerifyRoundtrip(t *testing.T) {
	pub, priv := mustGenKey(t)
	devicePub, _ := mustGenKey(t)

	signed, err := Sign(newTestLicense(devicePub), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := Verify(signed, pub); err != nil {
		t.Errorf("Verify on freshly signed license: %v", err)
	}
}

func TestVerifyDetectsTamperedEmail(t *testing.T) {
	pub, priv := mustGenKey(t)
	devicePub, _ := mustGenKey(t)

	signed, err := Sign(newTestLicense(devicePub), priv)
	if err != nil {
		t.Fatal(err)
	}
	signed.License.Email = "attacker@example.com"
	if err := Verify(signed, pub); err == nil {
		t.Error("Verify should fail after email tamper")
	}
}

func TestVerifyDetectsTamperedProducts(t *testing.T) {
	pub, priv := mustGenKey(t)
	devicePub, _ := mustGenKey(t)

	signed, err := Sign(newTestLicense(devicePub), priv)
	if err != nil {
		t.Fatal(err)
	}
	signed.License.Products = append(signed.License.Products, "sandbox")
	if err := Verify(signed, pub); err == nil {
		t.Error("Verify should fail after products tamper")
	}
}

func TestVerifyRejectsWrongPubkey(t *testing.T) {
	_, priv := mustGenKey(t)
	otherPub, _ := mustGenKey(t)
	devicePub, _ := mustGenKey(t)

	signed, err := Sign(newTestLicense(devicePub), priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(signed, otherPub); err == nil {
		t.Error("Verify should fail with mismatched public key")
	}
}

func TestVerifyRejectsUnknownSchemaVersion(t *testing.T) {
	pub, priv := mustGenKey(t)
	devicePub, _ := mustGenKey(t)

	lic := newTestLicense(devicePub)
	lic.SchemaVersion = 99
	signed, err := Sign(lic, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(signed, pub); err == nil {
		t.Error("Verify should reject unknown schema_version")
	}
}

func TestVerifyRejectsNilAndBadPubkey(t *testing.T) {
	pub, _ := mustGenKey(t)
	if err := Verify(nil, pub); err == nil {
		t.Error("Verify(nil) should error")
	}

	_, priv := mustGenKey(t)
	devicePub, _ := mustGenKey(t)
	signed, _ := Sign(newTestLicense(devicePub), priv)
	if err := Verify(signed, ed25519.PublicKey([]byte{1, 2, 3})); err == nil {
		t.Error("Verify with undersized pubkey should error")
	}
}

func TestSignRejectsBadPrivateKey(t *testing.T) {
	devicePub, _ := mustGenKey(t)
	if _, err := Sign(newTestLicense(devicePub), ed25519.PrivateKey([]byte{1, 2, 3})); err == nil {
		t.Error("Sign with undersized privkey should error")
	}
}

func TestIsExpired(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	past := now.Add(-24 * time.Hour)
	future := now.Add(24 * time.Hour)

	cases := []struct {
		name    string
		expires *time.Time
		want    bool
	}{
		{"forever never expires", nil, false},
		{"expired yesterday", &past, true},
		{"expires tomorrow", &future, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := License{ExpiresAt: c.expires}
			if got := l.IsExpired(now); got != c.want {
				t.Errorf("IsExpired = %v, want %v", got, c.want)
			}
		})
	}
}

func TestIsForever(t *testing.T) {
	if !(License{}).IsForever() {
		t.Error("License with nil ExpiresAt should be forever")
	}
	t1 := time.Now()
	if (License{ExpiresAt: &t1}).IsForever() {
		t.Error("License with non-nil ExpiresAt should not be forever")
	}
}

func TestCanonicalNormalizesSubSecondPrecision(t *testing.T) {
	devicePub, _ := mustGenKey(t)

	base := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	withNanos := base.Add(123456 * time.Nanosecond)
	expires := time.Date(2027, 5, 27, 12, 0, 0, 0, time.UTC)

	a := License{
		SchemaVersion: SchemaVersion,
		LicenseID:     "id",
		Email:         "x@y",
		Tier:          TierYearly,
		IssuedAt:      base,
		ExpiresAt:     &expires,
		DevicePubkey:  devicePub,
		Products:      []string{"interpose"},
	}
	b := a
	b.IssuedAt = withNanos

	ca, err := a.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	cb, err := b.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if string(ca) != string(cb) {
		t.Errorf("Canonical not stable across sub-second precision:\n  a=%s\n  b=%s", ca, cb)
	}
}

func TestCanonicalNormalizesTimezone(t *testing.T) {
	devicePub, _ := mustGenKey(t)

	utc := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	jst := time.FixedZone("JST", 9*60*60)
	sameInstantJST := utc.In(jst)
	expires := time.Date(2027, 5, 27, 12, 0, 0, 0, time.UTC)

	a := License{
		SchemaVersion: SchemaVersion,
		LicenseID:     "id",
		Email:         "x@y",
		Tier:          TierYearly,
		IssuedAt:      utc,
		ExpiresAt:     &expires,
		DevicePubkey:  devicePub,
		Products:      []string{"interpose"},
	}
	b := a
	b.IssuedAt = sameInstantJST

	ca, _ := a.Canonical()
	cb, _ := b.Canonical()
	if string(ca) != string(cb) {
		t.Errorf("Canonical should normalize timezone:\n  a=%s\n  b=%s", ca, cb)
	}
}

func TestSignedRoundTripsThroughJSON(t *testing.T) {
	pub, priv := mustGenKey(t)
	devicePub, _ := mustGenKey(t)

	signed, err := Sign(newTestLicense(devicePub), priv)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	var got Signed
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if err := Verify(&got, pub); err != nil {
		t.Errorf("Verify after JSON round-trip: %v", err)
	}
}
