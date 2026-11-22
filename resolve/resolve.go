// SPDX-License-Identifier: Apache-2.0

// Package resolve pulls the catalogs a Gemara artifact imports and verifies
// each one's signature the way a primary artifact is verified: against the
// signer identity the hub recorded for that import's own coordinate at
// ingest, never the importing artifact's. The decision is ADR-0122 in
// revanite-io/semaphore (superseding ADR-0080 for imports).
//
// Selection and host recognition are package refs (the latter is
// grc-store-protocol/refurl). Only two kinds of import are skipped and
// reported in Result.Skipped: a reference to a host that is neither a
// grc.store host nor the targeted hub, and an import the hub does not have.
// "Does not have" means the hub's catalog API answers 404 or 410, lists no
// release at the pinned version, or marks that release yanked (tombstoned).
// Every other failure fails the whole resolution closed with an
// *ImportError naming the import: a malformed reference (an unparseable url,
// one with no host, or a grc.store or target-hub url whose path is not
// /{namespace}/{catalog_id}), no version pinned, no recorded signer or
// indexed digest, no signature, a signature that does not verify, or a hub,
// registry or transport error (a registry 404 for a release the hub lists
// included). An imports field that cannot be read fails closed naming the
// artifact. The bytes pulled are those of the digest the hub indexed for
// the version. Nothing is retried here beyond the registry client's own
// transport retry. Resolution is direct-only: an import's own imports are
// not followed.
//
// Callers must surface every Result.Skipped entry with its reason and must
// not present the result as complete while Skipped is non-empty.
package resolve

import (
	"context"
	"errors"
	"fmt"
	neturl "net/url"
	"os"

	gbundle "github.com/gemaraproj/go-gemara/bundle"

	"github.com/gemaraproj/grc-store-clientkit/bundle"
	"github.com/gemaraproj/grc-store-clientkit/hub"
	"github.com/gemaraproj/grc-store-clientkit/keyless"
	"github.com/gemaraproj/grc-store-clientkit/refs"
	"github.com/revanite-io/grc-store-protocol/refurl"
)

// verifier is the signature check. Unexported, so a caller cannot swap in a
// check that always passes (ADR-0122 decision 8: no opt-out); tests set it.
type verifier interface {
	Verify(ctx context.Context, signatureBundle []byte, artifactDigest string, id keyless.IdentityPolicy) (keyless.VerifyResult, error)
}

// Resolver resolves imports against one hub.
type Resolver struct {
	// Hub is the target. Its BaseURL decides which reference hosts resolve;
	// its Bearer, when set, mints pull tokens for private namespaces.
	Hub *hub.Client
	// Verifier defaults to keyless.NewVerifier (the pinned public-good root).
	// It is the concrete type, so it always carries the production SCT,
	// Rekor and timestamp requirements.
	Verifier *keyless.Verifier

	verify verifier // test seam; nil in production
}

// Import is one pulled and verified import.
type Import struct {
	ReferenceID    string // the MappingReference id
	URL            string
	Namespace      string
	CatalogID      string
	Version        string
	Bundle         *gbundle.Bundle
	ManifestDigest string
	Signer         string // canonical identity recovered from the verified certificate
	License        string // the release's license on the hub, "" when none
}

// Skipped is an import that was reported and not resolved.
type Skipped struct {
	ReferenceID string
	URL         string
	Reason      string
}

// Result is what Imports resolved. Notes are non-fatal parse caveats.
type Result struct {
	Imports []Import
	Skipped []Skipped
	Notes   []string
}

// ImportError is a fail-closed resolution failure for one import.
type ImportError struct {
	// Import is <namespace>/<catalog-id>@<version>; the mapping reference id
	// when its url is malformed; or "artifact <metadata.id>" when the
	// artifact's imports field cannot be read.
	Import string
	Err    error
}

func (e *ImportError) Error() string { return fmt.Sprintf("import %s: %v", e.Import, e.Err) }
func (e *ImportError) Unwrap() error { return e.Err }

// pull is swapped by tests for an in-memory registry.
var pull = func(ctx context.Context, r bundle.Registry, repository, tag string) (*bundle.Pulled, error) {
	return r.Pull(ctx, repository, tag)
}

// Imports resolves every `imports` reference in body (one Gemara artifact,
// YAML or JSON) at the version pinned in metadata.mapping-references.
// It returns nothing but the error if any import fails closed.
func (r *Resolver) Imports(ctx context.Context, body []byte) (*Result, error) {
	if r.Hub == nil || r.Hub.BaseURL == "" {
		return nil, errors.New("hub target is required")
	}
	u, err := neturl.Parse(r.Hub.BaseURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("hub base URL %q has no host", r.Hub.BaseURL)
	}
	verifier := r.verify
	if verifier == nil {
		v := r.Verifier
		if v == nil {
			if v, err = keyless.NewVerifier(0); err != nil {
				return nil, err
			}
		}
		verifier = v
	}
	a, err := refs.Scan(body)
	if err != nil {
		return nil, err
	}
	// An imports field we cannot read would otherwise resolve as "no imports".
	if a.ImportsUnreadable {
		return nil, &ImportError{"artifact " + a.ID, fmt.Errorf("cannot read its imports: %v", a.Notes)}
	}

	res := &Result{Notes: a.Notes}
	var reg *bundle.Registry // discovered on the first pull
	seen := map[string]bool{}
	for _, s := range a.Select(refs.ImportsOnly) {
		ns, id, ok, reason := refs.Recognize(s.URL, u.Host)
		if !ok {
			// Only a foreign host is a legitimate skip; a malformed
			// reference fails closed (ruled 2026-11-21, ADR-0122).
			if foreignHost(s.URL, u.Host) {
				res.Skipped = append(res.Skipped, Skipped{s.ID, s.URL, reason})
				continue
			}
			return nil, &ImportError{s.ID, errors.New(reason)}
		}
		coord := fmt.Sprintf("%s/%s@%s", ns, id, s.Version)
		if s.Version == "" {
			return nil, &ImportError{coord, errors.New("mapping reference pins no version")}
		}
		if seen[coord] {
			continue
		}
		seen[coord] = true

		cat, err := r.Hub.GetCatalog(ctx, ns, id)
		if errors.Is(err, hub.ErrCatalogNotFound) || errors.Is(err, hub.ErrCatalogTombstoned) {
			res.Skipped = append(res.Skipped, Skipped{s.ID, s.URL, err.Error()})
			continue
		}
		if err != nil {
			return nil, &ImportError{coord, err}
		}
		rel := cat.ReleaseFor(s.Version)
		if rel == nil {
			res.Skipped = append(res.Skipped, Skipped{s.ID, s.URL, "version " + s.Version + " is not published on the hub"})
			continue
		}
		if rel.TombstonedAt != "" {
			res.Skipped = append(res.Skipped, Skipped{s.ID, s.URL, "version " + s.Version + " was yanked"})
			continue
		}
		if rel.ManifestDigest == "" {
			return nil, &ImportError{coord, errors.New("hub record lists no manifest digest for this version")}
		}
		policy, err := keyless.PolicyFromRecordedIdentity(cat.SignerIdentity)
		if err != nil {
			return nil, &ImportError{coord, err}
		}

		if reg == nil {
			d, err := hub.Discover(ctx, r.Hub.BaseURL)
			if err != nil {
				return nil, &ImportError{coord, err}
			}
			host, plain, err := hub.Registry(d)
			if err != nil {
				return nil, &ImportError{coord, err}
			}
			reg = &bundle.Registry{Host: host, PlainHTTP: plain}
		}
		repo := ns + "/" + id
		dial := *reg
		// A credential the caller set in the environment wins over a minted
		// one; otherwise mint per repository (registry tokens are scoped to one).
		if !userRegistryCredential() {
			tok, err := r.Hub.RegistryToken(ctx, repo, []string{"pull"})
			if err != nil {
				return nil, &ImportError{coord, fmt.Errorf("fetching registry pull token: %w", err)}
			}
			dial.Token = tok.Token
		}
		// Pull the digest the hub indexed, not whatever the tag names now
		// (semaphore ADR-0078: the index's digest is the authority).
		p, err := pull(ctx, dial, repo, rel.ManifestDigest)
		if err != nil {
			return nil, &ImportError{coord, err}
		}
		if p.ManifestDigest != rel.ManifestDigest {
			return nil, &ImportError{coord, fmt.Errorf("registry served %s, hub indexed %s", p.ManifestDigest, rel.ManifestDigest)}
		}
		vr, err := verifier.Verify(ctx, p.Signature, p.ManifestDigest, policy)
		if err != nil {
			return nil, &ImportError{coord, err}
		}
		res.Imports = append(res.Imports, Import{
			ReferenceID: s.ID, URL: s.URL, Namespace: ns, CatalogID: id, Version: s.Version,
			Bundle: p.Bundle, ManifestDigest: p.ManifestDigest, Signer: vr.Identity, License: rel.License,
		})
	}
	return res, nil
}

// foreignHost reports whether refURL parses with a host that is neither a
// grc.store host nor targetHost, the same host test refs.Recognize applies.
func foreignHost(refURL, targetHost string) bool {
	u, err := neturl.Parse(refURL)
	return err == nil && u.Host != "" && !refurl.IsGrcStoreHost(u.Host) && u.Host != targetHost
}

func userRegistryCredential() bool {
	if os.Getenv(bundle.RegistryTokenEnv) != "" {
		return true
	}
	return os.Getenv(bundle.RegistryUsernameEnv) != "" && os.Getenv(bundle.RegistryPasswordEnv) != ""
}
