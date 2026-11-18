// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	gbundle "github.com/gemaraproj/go-gemara/bundle"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/revanite-io/grc-store-protocol/limits"
	"github.com/revanite-io/grc-store-protocol/mediatype"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry"
)

// Pulled is one bundle read from a registry, with the signature bundle
// attached to that exact manifest.
type Pulled struct {
	Bundle         *gbundle.Bundle
	ManifestDigest string // "sha256:<hex>"; the signature's subject
	// Signature is the Sigstore bundle JSON from the manifest's signature
	// referrer, or nil when none is attached (unsigned).
	Signature []byte
}

// Pull resolves reference (a tag or a digest) in repository once and reads
// the bundle and its signature by the resolved digest, so the bytes returned
// are the bytes the signature is checked against even if a tag moves mid-pull.
func (r Registry) Pull(ctx context.Context, repository, tag string) (*Pulled, error) {
	target, err := openRepository(r, repository)
	if err != nil {
		return nil, err
	}
	return pull(ctx, target, tag)
}

func pull(ctx context.Context, target oras.ReadOnlyTarget, tag string) (*Pulled, error) {
	desc, err := target.Resolve(ctx, tag)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", tag, err)
	}
	b, err := gbundle.Unpack(ctx, pinned{target, desc}, tag)
	if err != nil {
		return nil, err
	}
	sig, err := signatureBundle(ctx, target, desc)
	if err != nil {
		return nil, err
	}
	return &Pulled{Bundle: b, ManifestDigest: desc.Digest.String(), Signature: sig}, nil
}

// pinned answers every Resolve with the descriptor already resolved, so
// Unpack reads that manifest and never re-resolves the tag.
type pinned struct {
	oras.ReadOnlyTarget
	desc ocispec.Descriptor
}

func (p pinned) Resolve(context.Context, string) (ocispec.Descriptor, error) { return p.desc, nil }

// signatureBundle returns the Sigstore bundle bytes from subject's signature
// referrer, nil when there is none, and an error for a transport failure or
// a malformed referrer so the caller fails closed. Both artifactType stamps
// are accepted (cosign 2.6.x CosignSignReferrer, cosign 3.x and this
// module's Publish SigstoreBundle). Moved from grcli's internal/registry.
func signatureBundle(ctx context.Context, target oras.ReadOnlyTarget, subject ocispec.Descriptor) ([]byte, error) {
	gs, ok := target.(content.ReadOnlyGraphStorage)
	if !ok {
		return nil, nil
	}
	all, err := registry.Referrers(ctx, gs, subject, "")
	if err != nil {
		return nil, fmt.Errorf("listing signature referrers: %w", err)
	}
	var sigs []ocispec.Descriptor
	for _, r := range all {
		if r.ArtifactType == mediatype.CosignSignReferrer || r.ArtifactType == mediatype.SigstoreBundle {
			sigs = append(sigs, r)
		}
	}
	if len(sigs) == 0 {
		return nil, nil
	}
	manifestBytes, err := fetchCapped(ctx, target, sigs[0])
	if err != nil {
		return nil, fmt.Errorf("fetching signature manifest: %w", err)
	}
	var m ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return nil, fmt.Errorf("parsing signature manifest: %w", err)
	}
	for _, layer := range m.Layers {
		if layer.MediaType == mediatype.SigstoreBundle {
			blob, err := fetchCapped(ctx, target, layer)
			if err != nil {
				return nil, fmt.Errorf("fetching signature bundle: %w", err)
			}
			return blob, nil
		}
	}
	return nil, fmt.Errorf("signature referrer %s carries no %s layer", sigs[0].Digest, mediatype.SigstoreBundle)
}

// fetchCapped reads a small descriptor (referrer manifest, bundle JSON).
func fetchCapped(ctx context.Context, target oras.ReadOnlyTarget, desc ocispec.Descriptor) ([]byte, error) {
	rc, err := target.Fetch(ctx, desc)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	return io.ReadAll(io.LimitReader(rc, limits.MaxPluginBlobBytes))
}
