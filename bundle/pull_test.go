// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/revanite-io/grc-store-protocol/mediatype"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/errdef"
)

func TestPull_ReturnsBundleDigestAndSignature(t *testing.T) {
	ctx := context.Background()
	sig := []byte(`{"the":"signature"}`)
	for _, artifactType := range []string{mediatype.SigstoreBundle, mediatype.CosignSignReferrer} {
		store := memory.New()
		res, err := pack(ctx, store, "v1", testInput)
		if err != nil {
			t.Fatal(err)
		}
		// Provenance is a referrer too; it must never be read as the signature.
		if err := AttachReferrer(ctx, store, res.Manifest, ProvenanceArtifactType, []byte(`{"p":1}`)); err != nil {
			t.Fatal(err)
		}
		if err := attachWithLayer(ctx, store, res, artifactType, mediatype.SigstoreBundle, sig); err != nil {
			t.Fatal(err)
		}
		got, err := pull(ctx, store, "v1")
		if err != nil {
			t.Fatal(err)
		}
		if got.ManifestDigest != res.ManifestDigest || string(got.Signature) != string(sig) {
			t.Errorf("%s: pulled = %s %s", artifactType, got.ManifestDigest, got.Signature)
		}
		if string(got.Bundle.Source.Data) != string(testInput.Body) {
			t.Errorf("%s: source = %q", artifactType, got.Bundle.Source.Data)
		}
	}
}

func TestPull_UnsignedAndMalformed(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	res, err := pack(ctx, store, "v1", testInput)
	if err != nil {
		t.Fatal(err)
	}
	if err := AttachReferrer(ctx, store, res.Manifest, "application/spdx+json", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	got, err := pull(ctx, store, "v1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Signature != nil {
		t.Fatalf("unsigned: sig = %s, want nil", got.Signature)
	}
	// A signature-typed referrer without a bundle layer is malformed, never "unsigned".
	if err := attachWithLayer(ctx, store, res, mediatype.CosignSignReferrer, "application/octet-stream", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := pull(ctx, store, "v1"); err == nil || !strings.Contains(err.Error(), "carries no") {
		t.Fatalf("malformed referrer: err = %v", err)
	}
	if _, err := pull(ctx, store, "missing"); err == nil {
		t.Fatal("missing tag: want error")
	}
}

// attachWithLayer pushes a signature-shaped referrer manifest by hand, since
// oras.PackManifest rejects the cosign 2.6.x artifactType (a URL).
func attachWithLayer(ctx context.Context, store *memory.Store, res *Result, artifactType, layerType string, blob []byte) error {
	push := func(mediaType string, data []byte) (ocispec.Descriptor, error) {
		d := ocispec.Descriptor{MediaType: mediaType, Digest: godigest.FromBytes(data), Size: int64(len(data))}
		if err := store.Push(ctx, d, bytes.NewReader(data)); err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
			return d, err
		}
		return d, nil
	}
	layer, err := push(layerType, blob)
	if err != nil {
		return err
	}
	cfg, err := push(ocispec.MediaTypeEmptyJSON, []byte("{}"))
	if err != nil {
		return err
	}
	subject := res.Manifest
	m, err := json.Marshal(ocispec.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: artifactType,
		Config:       cfg,
		Layers:       []ocispec.Descriptor{layer},
		Subject:      &subject,
	})
	if err != nil {
		return err
	}
	d := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, ArtifactType: artifactType, Digest: godigest.FromBytes(m), Size: int64(len(m))}
	return store.Push(ctx, d, bytes.NewReader(m))
}
