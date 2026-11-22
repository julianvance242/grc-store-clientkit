// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/revanite-io/grc-store-protocol/mediatype"
	"oras.land/oras-go/v2"
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

// hostile serves same-length tampered bytes for the artifact body, and moves the
// tag to other after the first Resolve.
type hostile struct {
	oras.ReadOnlyTarget
	tamper   bool
	resolves int
	other    ocispec.Descriptor
}

func (h *hostile) Resolve(ctx context.Context, ref string) (ocispec.Descriptor, error) {
	h.resolves++
	if h.resolves > 1 {
		return h.other, nil
	}
	return h.ReadOnlyTarget.Resolve(ctx, ref)
}

func (h *hostile) Fetch(ctx context.Context, d ocispec.Descriptor) (io.ReadCloser, error) {
	rc, err := h.ReadOnlyTarget.Fetch(ctx, d)
	if err != nil || !h.tamper {
		return rc, err
	}
	b, err := io.ReadAll(rc)
	_ = rc.Close()
	// Same length, valid YAML, different content: only a digest check catches it.
	return io.NopCloser(bytes.NewReader(bytes.ReplaceAll(b, []byte("my-log"), []byte("my-lox")))), err
}

func TestPull_VerifiesBytesAndPinsTheResolvedManifest(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	res, err := pack(ctx, store, "v1", testInput)
	if err != nil {
		t.Fatal(err)
	}
	other, err := pack(ctx, store, "v2", func() Input {
		in := testInput
		in.Body = []byte("metadata:\n  id: my-log\n  version: 2.0.0\n")
		return in
	}())
	if err != nil {
		t.Fatal(err)
	}
	// Bytes that do not hash to their descriptor fail the pull.
	if _, err := pull(ctx, &hostile{ReadOnlyTarget: store, tamper: true}, "v1"); err == nil {
		t.Fatal("tampered layer: want error")
	}
	// A tag that moves after the first Resolve does not change what is read.
	got, err := pull(ctx, &hostile{ReadOnlyTarget: store, other: other.Manifest}, "v1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ManifestDigest != res.ManifestDigest || string(got.Bundle.Source.Data) != string(testInput.Body) {
		t.Errorf("pulled %s %q, want the first-resolved manifest", got.ManifestDigest, got.Bundle.Source.Data)
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

func TestPull_SizeCapIsSummedAcrossBlobs(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	res, err := pack(ctx, store, "v1", testInput)
	if err != nil {
		t.Fatal(err)
	}
	m := res.Manifest
	// The cap is shared: room for exactly one read of the manifest, not two.
	p := &pinned{ReadOnlyTarget: store, desc: m, remaining: m.Size}
	if _, err := p.Fetch(ctx, m); err != nil {
		t.Fatalf("at the cap: %v", err)
	}
	if _, err := p.Fetch(ctx, m); !errors.Is(err, ErrPullTooLarge) {
		t.Errorf("over the summed cap: err = %v", err)
	}
	neg := m
	neg.Size = -1
	if _, err := (&pinned{ReadOnlyTarget: store, desc: m, remaining: MaxPullBytes}).Fetch(ctx, neg); !errors.Is(err, ErrPullTooLarge) {
		t.Errorf("negative size: err = %v", err)
	}
}

// The cap is enforced inside Pull: a manifest whose layer claims more than
// MaxPullBytes fails before that layer is fetched.
func TestPull_SizeCapThroughPull(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	res, err := pack(ctx, store, "v1", testInput)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := store.Fetch(ctx, res.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	var m ocispec.Manifest
	err = json.NewDecoder(rc).Decode(&m)
	_ = rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	m.Layers[0].Size = MaxPullBytes + 1
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	big := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: godigest.FromBytes(b), Size: int64(len(b))}
	if err := store.Push(ctx, big, bytes.NewReader(b)); err != nil {
		t.Fatal(err)
	}
	if err := store.Tag(ctx, big, "big"); err != nil {
		t.Fatal(err)
	}
	if _, err := pull(ctx, store, "big"); !errors.Is(err, ErrPullTooLarge) {
		t.Fatalf("err = %v, want ErrPullTooLarge", err)
	}
}

// With several signature referrers on one manifest (a re-sign, or cosign
// plus Publish), Pull returns one of their bundles, never the provenance.
func TestPull_MultipleSignatureReferrers(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	res, err := pack(ctx, store, "v1", testInput)
	if err != nil {
		t.Fatal(err)
	}
	if err := AttachReferrer(ctx, store, res.Manifest, ProvenanceArtifactType, []byte(`{"p":1}`)); err != nil {
		t.Fatal(err)
	}
	sigA, sigB := []byte(`{"sig":"a"}`), []byte(`{"sig":"b"}`)
	if err := attachWithLayer(ctx, store, res, mediatype.SigstoreBundle, mediatype.SigstoreBundle, sigA); err != nil {
		t.Fatal(err)
	}
	if err := attachWithLayer(ctx, store, res, mediatype.CosignSignReferrer, mediatype.SigstoreBundle, sigB); err != nil {
		t.Fatal(err)
	}
	got, err := pull(ctx, store, "v1")
	if err != nil {
		t.Fatal(err)
	}
	if s := string(got.Signature); s != string(sigA) && s != string(sigB) {
		t.Fatalf("signature = %q, want one of the two signature bundles", s)
	}
}
