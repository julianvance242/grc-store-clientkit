// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"context"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/gemaraproj/grc-store-clientkit/hub"
)

// TestLive_CCCSecMgmtImportsCore runs against a real hub with the real
// Sigstore verifier. Off by default: GRC_STORE_LIVE_HUB=https://hub.grc.store
// go test ./resolve -run Live
func TestLive_CCCSecMgmtImportsCore(t *testing.T) {
	hubURL := os.Getenv("GRC_STORE_LIVE_HUB")
	if hubURL == "" {
		t.Skip("GRC_STORE_LIVE_HUB not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, hubURL+"/v1/catalogs/finos-ccc/ccc.secmgmt.controls/versions/v2026.11", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("fetching the primary body: %d %v", resp.StatusCode, err)
	}

	res, err := (&Resolver{Hub: hub.New(hubURL, "")}).Imports(ctx, body)
	if err != nil {
		t.Fatal(err)
	}
	const want = "keyless:https://token.actions.githubusercontent.com#https://github.com/finos/common-cloud-controls/.github/workflows/release.yml"
	if len(res.Imports) != 1 {
		t.Fatalf("imports = %+v, skipped = %+v", res.Imports, res.Skipped)
	}
	got := res.Imports[0]
	if got.Namespace != "finos-ccc" || got.CatalogID != "ccc.core.controls" || got.Version != "v2026.11" || got.Signer != want {
		t.Fatalf("import = %s/%s@%s signed by %s", got.Namespace, got.CatalogID, got.Version, got.Signer)
	}
	if len(got.Bundle.Source.Data) == 0 {
		t.Fatal("import bundle has no source file")
	}
	t.Logf("verified %s/%s@%s (%s), signer %s", got.Namespace, got.CatalogID, got.Version, got.ManifestDigest, got.Signer)
}
