// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetCatalog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("catalog reads are public; no bearer may be sent")
		}
		switch r.URL.Path {
		case "/v1/catalogs/acme/core":
			_, _ = w.Write([]byte(`{"namespace":"acme","catalog_id":"core","signer_identity":"keyless:i#w",
				"releases":[{"version":"v1","license":"MIT"}]}`))
		case "/v1/catalogs/acme/gone":
			w.WriteHeader(http.StatusGone)
		case "/v1/catalogs/acme/broken":
			w.WriteHeader(http.StatusBadGateway)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c := New(srv.URL, "bearer")
	ctx := context.Background()

	cat, err := c.GetCatalog(ctx, "acme", "core")
	if err != nil {
		t.Fatal(err)
	}
	if cat.SignerIdentity != "keyless:i#w" || cat.ReleaseFor("v1").License != "MIT" || cat.ReleaseFor("v2") != nil {
		t.Errorf("catalog = %+v", cat)
	}
	if _, err := c.GetCatalog(ctx, "acme", "missing"); !errors.Is(err, ErrCatalogNotFound) {
		t.Errorf("404: err = %v", err)
	}
	if _, err := c.GetCatalog(ctx, "acme", "gone"); !errors.Is(err, ErrCatalogTombstoned) {
		t.Errorf("410: err = %v", err)
	}
	var se *StatusError
	if _, err := c.GetCatalog(ctx, "acme", "broken"); !errors.As(err, &se) || se.Status != http.StatusBadGateway {
		t.Errorf("502: err = %v", err)
	}
}
