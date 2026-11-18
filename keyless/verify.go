// SPDX-License-Identifier: Apache-2.0

package keyless

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gemaraproj/grc-store-clientkit/trustroot"
	"github.com/revanite-io/grc-store-protocol/identity"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// The verify half of this package was moved from grcli's internal/sigverify,
// which mirrors the hub's internal/sigverify. The one deliberate difference
// from the hub: the hub verifies identity-agnostically and pins the signer
// it extracts (TOFU at ingest); a consumer already knows the signer to
// expect, so it pins SAN + issuer in the sigstore-go policy and a valid
// signature by the wrong identity is rejected.

// ErrUnsigned is returned when there is no signature bundle to verify.
var ErrUnsigned = errors.New("artifact is not signed")

// VerifyResult carries the canonical keyless identity
// ("keyless:<issuer>#<workflow-path>", ref stripped) recovered from the
// verified certificate, in the form the hub records (grc-store-protocol/identity).
type VerifyResult struct {
	Identity string
}

const defaultVerifyTimeout = 15 * time.Second

// Verifier verifies a Sigstore bundle over an artifact digest against a
// trust root, requiring a transparency-log entry, an observed timestamp and
// (in production) an SCT, and pinning the expected signer.
type Verifier struct {
	verifier *verify.Verifier
	timeout  time.Duration
	// requireSCT is false only for the unexported test constructor
	// (VirtualSigstore certs carry no SCT); kept so tests can assert the
	// exported constructors never relax it.
	requireSCT bool
}

// IdentityPolicy pins the expected signer. Exactly one of SAN (exact match)
// or SANRegexp (unanchored regexp, so the caller anchors it) is set; Issuer
// is always an exact match.
type IdentityPolicy struct {
	SAN       string
	SANRegexp string
	Issuer    string
}

func (ip IdentityPolicy) certificateIdentity() (verify.CertificateIdentity, error) {
	if ip.Issuer == "" {
		return verify.CertificateIdentity{}, errors.New("identity policy has no issuer")
	}
	if (ip.SAN == "") == (ip.SANRegexp == "") {
		return verify.CertificateIdentity{}, errors.New("identity policy must set exactly one of SAN or SANRegexp")
	}
	return verify.NewShortCertificateIdentity(ip.Issuer, "", ip.SAN, ip.SANRegexp)
}

// ErrNoRecordedSigner is returned by PolicyFromRecordedIdentity for an empty
// identity: the hub has recorded no signer for the coordinate, so there is
// nothing to pin and the caller must fail closed.
var ErrNoRecordedSigner = errors.New("hub has no recorded signer identity")

// PolicyFromRecordedIdentity turns the canonical signer identity a hub
// recorded at ingest ("keyless:<issuer>#<workflow-path>") into the policy
// that pins it: exact issuer, and the workflow path anchored as
// "^<path>@" so any git ref of that workflow verifies but nothing wider.
// This is the zero-flag trust source of ADR-0048.
func PolicyFromRecordedIdentity(canonical string) (IdentityPolicy, error) {
	if canonical == "" {
		return IdentityPolicy{}, ErrNoRecordedSigner
	}
	issuer, workflowPath, err := identity.ParseKeyless(canonical)
	if err != nil {
		return IdentityPolicy{}, fmt.Errorf("recorded signer identity %q is not a keyless identity: %w", canonical, err)
	}
	if issuer == "" || workflowPath == "" {
		return IdentityPolicy{}, fmt.Errorf("recorded signer identity %q is malformed (expected \"keyless:<issuer>#<workflow-path>\")", canonical)
	}
	return IdentityPolicy{SANRegexp: "^" + regexp.QuoteMeta(workflowPath) + "@", Issuer: issuer}, nil
}

// NewVerifier builds a verifier over the pinned public-good trust root
// (package trustroot). timeout <= 0 means the default.
func NewVerifier(timeout time.Duration) (*Verifier, error) {
	return newVerifierFromRoot(trustroot.Bytes(), "embedded", timeout)
}

// NewVerifierFromFile builds a verifier over a trusted_root.json on disk, for
// air-gapped deployments or a private Sigstore. The SCT/Rekor/timestamp
// policy is unchanged. An empty path errors rather than falling back to the
// embedded root, so a misconfiguration is never masked.
func NewVerifierFromFile(path string, timeout time.Duration) (*Verifier, error) {
	if path == "" {
		return nil, errors.New("trusted root file path is empty")
	}
	rootJSON, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trusted root file %q: %w", path, err)
	}
	return newVerifierFromRoot(rootJSON, path, timeout)
}

func newVerifierFromRoot(rootJSON []byte, src string, timeout time.Duration) (*Verifier, error) {
	tm, err := root.NewTrustedRootFromJSON(rootJSON)
	if err != nil {
		return nil, fmt.Errorf("parse %s trusted root: %w", src, err)
	}
	return newVerifier(tm, timeout, 1)
}

// newVerifier takes any trusted material so tests can pass a VirtualSigstore
// with sctThreshold 0; it is unexported so production always requires an SCT.
func newVerifier(tm root.TrustedMaterial, timeout time.Duration, sctThreshold int) (*Verifier, error) {
	opts := []verify.VerifierOption{
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	}
	if sctThreshold > 0 {
		opts = append(opts, verify.WithSignedCertificateTimestamps(sctThreshold))
	}
	v, err := verify.NewVerifier(tm, opts...)
	if err != nil {
		return nil, fmt.Errorf("build sigstore verifier: %w", err)
	}
	if timeout <= 0 {
		timeout = defaultVerifyTimeout
	}
	return &Verifier{verifier: v, timeout: timeout, requireSCT: sctThreshold > 0}, nil
}

// Verify checks signatureBundle (Sigstore bundle JSON) against artifactDigest
// ("sha256:<hex>") and the expected identity. Empty bundle bytes are
// ErrUnsigned. Any non-nil error means do not trust.
func (v *Verifier) Verify(ctx context.Context, signatureBundle []byte, artifactDigest string, id IdentityPolicy) (VerifyResult, error) {
	if len(signatureBundle) == 0 {
		return VerifyResult{}, ErrUnsigned
	}
	certID, err := id.certificateIdentity()
	if err != nil {
		return VerifyResult{}, fmt.Errorf("build identity policy: %w", err)
	}
	var b sgbundle.Bundle
	if err := b.UnmarshalJSON(signatureBundle); err != nil {
		return VerifyResult{}, fmt.Errorf("parse signature bundle: %w", err)
	}

	type outcome struct {
		res VerifyResult
		err error
	}
	ch := make(chan outcome, 1)
	go func() {
		res, err := v.verifyEntity(&b, artifactDigest, certID)
		ch <- outcome{res, err}
	}()
	timer := time.NewTimer(v.timeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return VerifyResult{}, ctx.Err()
	case <-timer.C:
		return VerifyResult{}, fmt.Errorf("signature verification timed out after %s", v.timeout)
	case r := <-ch:
		return r.res, r.err
	}
}

func (v *Verifier) verifyEntity(entity verify.SignedEntity, artifactDigest string, certID verify.CertificateIdentity) (VerifyResult, error) {
	digestBytes, err := hex.DecodeString(strings.TrimPrefix(artifactDigest, "sha256:"))
	if err != nil || len(digestBytes) != sha256.Size {
		return VerifyResult{}, fmt.Errorf("invalid artifact digest %q", artifactDigest)
	}
	policy := verify.NewPolicy(
		verify.WithArtifactDigest("sha256", digestBytes),
		verify.WithCertificateIdentity(certID),
	)
	res, err := v.verifier.Verify(entity, policy)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("signature verification failed: %w", err)
	}
	if res.Signature == nil || res.Signature.Certificate == nil {
		return VerifyResult{}, errors.New("verified signature carries no certificate identity (key-based signing is not accepted on the keyless path)")
	}
	cert := res.Signature.Certificate
	if cert.Issuer == "" || cert.SubjectAlternativeName == "" {
		return VerifyResult{}, errors.New("verified certificate is missing OIDC issuer or SAN")
	}
	return VerifyResult{Identity: identity.CanonicalKeylessIdentity(cert.Issuer, cert.SubjectAlternativeName)}, nil
}
