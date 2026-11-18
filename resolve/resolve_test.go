// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gbundle "github.com/gemaraproj/go-gemara/bundle"

	"github.com/gemaraproj/grc-store-clientkit/bundle"
	"github.com/gemaraproj/grc-store-clientkit/hub"
	"github.com/gemaraproj/grc-store-clientkit/keyless"
)

const (
	issuer   = "https://token.actions.githubusercontent.com"
	coreWF   = "https://github.com/acme/core/.github/workflows/release.yml"
	primeWF  = "https://github.com/acme/primary/.github/workflows/release.yml"
	coreSign = "keyless:" + issuer + "#" + coreWF
)

// body imports CORE (on grc.store) and EXT (elsewhere); THREATS is a plain
// mapping reference, not an import, so it is never resolved.
func body(coreVersion string) []byte {
	return fmt.Appendf(nil, `metadata:
  id: acme.primary
  type: ControlCatalog
  mapping-references:
    - {id: CORE, title: Core, version: %q, url: "https://grc.store/acme/core"}
    - {id: EXT, title: Ext, version: "1", url: "https://example.com/ext"}
    - {id: THREATS, title: Threats, version: v1, url: "https://grc.store/acme/threats"}
imports:
  - reference-id: CORE
    entries: [{reference-id: CORE.CN01}]
  - reference-id: EXT
    entries: [{reference-id: EXT.1}]
`, coreVersion)
}

type fakeVerifier struct {
	err    error
	policy keyless.IdentityPolicy
	digest string
	sig    string
}

func (f *fakeVerifier) Verify(_ context.Context, sig []byte, digest string, p keyless.IdentityPolicy) (keyless.VerifyResult, error) {
	f.policy, f.digest, f.sig = p, digest, string(sig)
	if f.err != nil {
		return keyless.VerifyResult{}, f.err
	}
	return keyless.VerifyResult{Identity: coreSign}, nil
}

type world struct {
	signer  string // signer_identity on acme/core
	indexed string // manifest_digest the hub lists for v1; "" means "sha256:core"
	served  string // digest the registry answers with; "" means the requested one
	tokens  []string
	pulls   []bundle.Registry
}

// digest is what the hub indexes for v1; "-" stands for "none listed".
func (w *world) digest() string {
	switch w.indexed {
	case "":
		return "sha256:core"
	case "-":
		return ""
	}
	return w.indexed
}

func setup(t *testing.T, w *world) *hub.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case hub.WellKnownPath:
			_, _ = rw.Write([]byte(`{"registry_url":"https://oci.test"}`))
		case "/v2/token":
			w.tokens = append(w.tokens, r.URL.Query().Get("scope"))
			_, _ = rw.Write([]byte(`{"token":"pull-token"}`))
		case "/v1/catalogs/acme/core":
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"namespace": "acme", "catalog_id": "core", "signer_identity": w.signer,
				"releases": []map[string]string{{"version": "v1", "license": "Apache-2.0", "manifest_digest": w.digest()}},
			})
		case "/v1/catalogs/acme/primary":
			t.Error("the importing artifact's record must never be read")
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	orig := pull
	pull = func(_ context.Context, r bundle.Registry, repository, tag string) (*bundle.Pulled, error) {
		w.pulls = append(w.pulls, r)
		if repository != "acme/core" || tag != w.digest() {
			t.Errorf("pull %s@%s, want the indexed digest", repository, tag)
		}
		served := w.served
		if served == "" {
			served = tag
		}
		return &bundle.Pulled{
			Bundle:         &gbundle.Bundle{Source: gbundle.File{Name: "core.yaml", Data: []byte("core")}},
			ManifestDigest: served,
			Signature:      []byte("sig"),
		}, nil
	}
	t.Cleanup(func() { pull = orig })
	return hub.New(srv.URL, "")
}

func TestImports_PullsAndVerifiesAgainstTheImportsOwnRecord(t *testing.T) {
	t.Setenv(bundle.RegistryTokenEnv, "")
	w := &world{signer: coreSign}
	v := &fakeVerifier{}
	res, err := (&Resolver{Hub: setup(t, w), Verifier: v}).Imports(context.Background(), body("v1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Imports) != 1 {
		t.Fatalf("imports = %+v", res.Imports)
	}
	got := res.Imports[0]
	if got.Namespace != "acme" || got.CatalogID != "core" || got.Version != "v1" || got.Signer != coreSign ||
		got.License != "Apache-2.0" || got.ManifestDigest != "sha256:core" || string(got.Bundle.Source.Data) != "core" {
		t.Errorf("import = %+v", got)
	}
	// Pinned to the import's own workflow, not the primary's.
	if v.policy.Issuer != issuer || !strings.Contains(v.policy.SANRegexp, "acme/core") || strings.Contains(v.policy.SANRegexp, primeWF) {
		t.Errorf("policy = %+v", v.policy)
	}
	if v.digest != "sha256:core" || v.sig != "sig" {
		t.Errorf("verified %s over %s", v.sig, v.digest)
	}
	if len(w.tokens) != 1 || w.tokens[0] != "repository:acme/core:pull" || w.pulls[0].Token != "pull-token" || w.pulls[0].Host != "oci.test" {
		t.Errorf("tokens = %v, pulls = %+v", w.tokens, w.pulls)
	}
	if len(res.Skipped) != 1 || res.Skipped[0].ReferenceID != "EXT" {
		t.Errorf("skipped = %+v", res.Skipped)
	}
}

func TestImports_FailsClosedNamingTheImport(t *testing.T) {
	cases := []struct {
		name    string
		signer  string
		version string
		verify  error
		want    error
		indexed string
		served  string
	}{
		{name: "no recorded signer", version: "v1", want: keyless.ErrNoRecordedSigner},
		{name: "unsigned", signer: coreSign, version: "v1", verify: keyless.ErrUnsigned, want: keyless.ErrUnsigned},
		{name: "bad signature", signer: coreSign, version: "v1", verify: errors.New("signature verification failed")},
		{name: "non-keyless record", signer: "key:abc", version: "v1"},
		{name: "no pinned version", signer: coreSign, version: ""},
		{name: "no indexed digest", signer: coreSign, version: "v1", indexed: "-"},
		{name: "registry serves other bytes", signer: coreSign, version: "v1", served: "sha256:other"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &world{signer: tc.signer, indexed: tc.indexed, served: tc.served}
			res, err := (&Resolver{Hub: setup(t, w), Verifier: &fakeVerifier{err: tc.verify}}).Imports(context.Background(), body(tc.version))
			var ie *ImportError
			if res != nil || !errors.As(err, &ie) || !strings.HasPrefix(ie.Import, "acme/core@") {
				t.Fatalf("res = %+v, err = %v; want an ImportError naming acme/core", res, err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestImports_UnpublishedImportIsSkipped(t *testing.T) {
	w := &world{signer: coreSign}
	res, err := (&Resolver{Hub: setup(t, w), Verifier: &fakeVerifier{}}).Imports(context.Background(), body("v9"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Imports) != 0 || len(res.Skipped) != 2 || len(w.pulls) != 0 {
		t.Errorf("res = %+v, pulls = %d", res, len(w.pulls))
	}
}

func TestImports_CallerCredentialSkipsTheMint(t *testing.T) {
	t.Setenv(bundle.RegistryTokenEnv, "mine")
	w := &world{signer: coreSign}
	if _, err := (&Resolver{Hub: setup(t, w), Verifier: &fakeVerifier{}}).Imports(context.Background(), body("v1")); err != nil {
		t.Fatal(err)
	}
	if len(w.tokens) != 0 || w.pulls[0].Token != "" {
		t.Errorf("tokens = %v, dial token = %q", w.tokens, w.pulls[0].Token)
	}
}
