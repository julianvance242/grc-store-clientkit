// SPDX-License-Identifier: Apache-2.0

package keyless

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gemaraproj/grc-store-clientkit/trustroot"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	ghaIssuer    = "https://token.actions.githubusercontent.com"
	workflowPath = "https://github.com/finos/common-cloud-controls/.github/workflows/release.yml"
	ghaSANRef    = workflowPath + "@refs/tags/v2026.11"
	recorded     = "keyless:" + ghaIssuer + "#" + workflowPath
)

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func newVS(t *testing.T) *ca.VirtualSigstore {
	t.Helper()
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	return vs
}

// testVerifier trusts the virtual sigstore; SCT threshold 0 because
// VirtualSigstore certs carry none.
func testVerifier(t *testing.T, vs *ca.VirtualSigstore) *Verifier {
	t.Helper()
	v, err := newVerifier(vs, 5*time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func certID(t *testing.T, ip IdentityPolicy) verify.CertificateIdentity {
	t.Helper()
	c, err := ip.certificateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func recordedPolicy(t *testing.T) IdentityPolicy {
	t.Helper()
	p, err := PolicyFromRecordedIdentity(recorded)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The DSSE in-toto statement this package's Signer emits verifies against
// the recorded-identity policy and yields the identity the hub records.
func TestVerify_RoundTripsSignerStatement(t *testing.T) {
	vs := newVS(t)
	d := digestOf([]byte("manifest"))
	stmt, err := Statement(d, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	entity, err := vs.Attest(ghaSANRef, ghaIssuer, stmt)
	if err != nil {
		t.Fatal(err)
	}
	res, err := testVerifier(t, vs).verifyEntity(entity, d, certID(t, recordedPolicy(t)))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Identity != recorded {
		t.Fatalf("identity = %q, want %q", res.Identity, recorded)
	}
}

func TestVerify_Rejects(t *testing.T) {
	artifact := []byte("artifact")
	cases := []struct {
		name   string
		san    string
		issuer string
		digest string
		policy IdentityPolicy
		root   bool // verify against a different trust root
	}{
		{name: "wrong digest", san: ghaSANRef, issuer: ghaIssuer, digest: digestOf([]byte("tampered"))},
		{name: "wrong workflow", san: "https://github.com/evil/repo/.github/workflows/release.yml@refs/tags/v1", issuer: ghaIssuer},
		{name: "wrong issuer", san: ghaSANRef, issuer: "https://gitlab.example.com"},
		{name: "prefixed workflow", san: "https://evil.example/" + ghaSANRef, issuer: ghaIssuer},
		{name: "sibling workflow path", san: workflowPath + "-x/.github/workflows/release.yml@refs/tags/v1", issuer: ghaIssuer},
		{name: "regexp dot is literal", san: "https://github.com/finos/common-cloud-controls/.github/workflowsXrelease.yml@refs/tags/v1", issuer: ghaIssuer},
		{name: "foreign trust root", san: ghaSANRef, issuer: ghaIssuer, root: true},
		{name: "bad digest format", san: ghaSANRef, issuer: ghaIssuer, digest: "not-a-digest"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vs := newVS(t)
			entity, err := vs.Sign(tc.san, tc.issuer, artifact)
			if err != nil {
				t.Fatal(err)
			}
			v := testVerifier(t, vs)
			if tc.root {
				v = testVerifier(t, newVS(t))
			}
			d := tc.digest
			if d == "" {
				d = digestOf(artifact)
			}
			if _, err := v.verifyEntity(entity, d, certID(t, recordedPolicy(t))); err == nil {
				t.Fatal("verified; want rejection")
			}
		})
	}
}

func TestVerify_AcceptsAnyRefOfRecordedWorkflow(t *testing.T) {
	for _, ref := range []string{"@refs/tags/v1.0.0", "@refs/heads/main"} {
		vs := newVS(t)
		artifact := []byte("a" + ref)
		entity, err := vs.Sign(workflowPath+ref, ghaIssuer, artifact)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := testVerifier(t, vs).verifyEntity(entity, digestOf(artifact), certID(t, recordedPolicy(t))); err != nil {
			t.Fatalf("%s: %v", ref, err)
		}
	}
}

func TestVerify_UnsignedAndMalformed(t *testing.T) {
	v := testVerifier(t, newVS(t))
	ctx := context.Background()
	p := recordedPolicy(t)
	if _, err := v.Verify(ctx, nil, digestOf([]byte("x")), p); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("nil bundle: err = %v, want ErrUnsigned", err)
	}
	if _, err := v.Verify(ctx, []byte("{not a bundle}"), digestOf([]byte("x")), p); err == nil || errors.Is(err, ErrUnsigned) {
		t.Fatalf("malformed bundle: err = %v, want a non-ErrUnsigned error", err)
	}
	if _, err := v.Verify(ctx, []byte("{}"), digestOf([]byte("x")), IdentityPolicy{Issuer: ghaIssuer}); err == nil {
		t.Fatal("policy with no SAN: want error")
	}
}

func TestPolicyFromRecordedIdentity(t *testing.T) {
	if _, err := PolicyFromRecordedIdentity(""); !errors.Is(err, ErrNoRecordedSigner) {
		t.Fatalf("empty: err = %v, want ErrNoRecordedSigner", err)
	}
	for _, bad := range []string{"key:abc", "keyless:no-separator", "keyless:#", "garbage"} {
		if _, err := PolicyFromRecordedIdentity(bad); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
	p := recordedPolicy(t)
	if p.Issuer != ghaIssuer || p.SAN != "" || p.SANRegexp == "" {
		t.Fatalf("policy = %+v", p)
	}
}

func TestIdentityPolicy_Validation(t *testing.T) {
	for _, ip := range []IdentityPolicy{
		{SAN: ghaSANRef},
		{Issuer: ghaIssuer},
		{SAN: ghaSANRef, SANRegexp: "^x@", Issuer: ghaIssuer},
	} {
		if _, err := ip.certificateIdentity(); err == nil {
			t.Errorf("%+v: want error", ip)
		}
	}
}

func TestProductionVerifiersRequireSCT(t *testing.T) {
	v, err := NewVerifier(0)
	if err != nil {
		t.Fatal(err)
	}
	if !v.requireSCT {
		t.Fatal("NewVerifier must require SCTs")
	}
	path := filepath.Join(t.TempDir(), "trusted_root.json")
	if err := os.WriteFile(path, trustroot.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err = NewVerifierFromFile(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !v.requireSCT {
		t.Fatal("NewVerifierFromFile must require SCTs")
	}
	if _, err := NewVerifierFromFile("", 0); err == nil {
		t.Fatal("empty path: want error")
	}
	if _, err := NewVerifierFromFile(filepath.Join(t.TempDir(), "missing.json"), 0); err == nil {
		t.Fatal("missing file: want error")
	}
}

// A real public-good Sigstore bundle: the signature on
// finos-ccc/ccc.core.controls@v2026.11 as published to grc.store.
const (
	realBundleFile = "testdata/ccc-core-controls-v2026.11.sigstore.json"
	realDigest     = "sha256:7c9e9cd59ca1f5d1d39062cb851c920d5cf07c3bc1d90fdf849fa0c5b2c15d04"
)

func realBundle(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(realBundleFile)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The exported Verify, end to end, with the production verifier over the
// embedded trust root (SCT, Rekor and timestamp all required).
func TestVerify_RealBundleEndToEnd(t *testing.T) {
	v, err := NewVerifier(0)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	res, err := v.Verify(ctx, realBundle(t), realDigest, recordedPolicy(t))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Identity != recorded {
		t.Fatalf("identity = %q, want %q", res.Identity, recorded)
	}
	if _, err := v.Verify(ctx, realBundle(t), digestOf([]byte("other")), recordedPolicy(t)); err == nil {
		t.Fatal("other digest: verified; want rejection")
	}
	other, err := PolicyFromRecordedIdentity("keyless:" + ghaIssuer + "#https://github.com/evil/repo/.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(ctx, realBundle(t), realDigest, other); err == nil {
		t.Fatal("other signer: verified; want rejection")
	}
}

func TestVerify_CancelledContext(t *testing.T) {
	v, err := NewVerifier(0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := v.Verify(ctx, realBundle(t), realDigest, recordedPolicy(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestVerify_Timeout(t *testing.T) {
	// 1ns elapses long before a real verification (signature, SCT, Rekor
	// checks) can finish, so the timer always wins the select.
	v, err := NewVerifier(time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Verify(context.Background(), realBundle(t), realDigest, recordedPolicy(t))
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v, want a timeout", err)
	}
}
