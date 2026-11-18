// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	neturl "net/url"
)

var (
	// ErrCatalogNotFound wraps a hub 404 for a catalog coordinate.
	ErrCatalogNotFound = errors.New("catalog not found")
	// ErrCatalogTombstoned wraps a hub 410: published, then yanked.
	ErrCatalogTombstoned = errors.New("catalog was yanked")
)

// Release is one published version in GET /v1/catalogs/{ns}/{id}.
type Release struct {
	Version        string `json:"version"`
	ManifestDigest string `json:"manifest_digest"`
	PushedAt       string `json:"pushed_at"`
	License        string `json:"license,omitempty"`
}

// Catalog is the subset of GET /v1/catalogs/{ns}/{id} clients read.
// Moved from grcli's internal/hub.
type Catalog struct {
	Namespace     string    `json:"namespace"`
	CatalogID     string    `json:"catalog_id"`
	Type          string    `json:"type"`
	Title         string    `json:"title"`
	LatestVersion string    `json:"latest_version"`
	Releases      []Release `json:"releases"`
	// SignerIdentity is the canonical keyless signer the hub verified and
	// pinned for this coordinate at ingest ("keyless:<issuer>#<workflow-path>").
	// Empty when no signed version has been ingested.
	SignerIdentity string `json:"signer_identity,omitempty"`
}

// ReleaseFor returns the release for version, or nil.
func (c *Catalog) ReleaseFor(version string) *Release {
	for i := range c.Releases {
		if c.Releases[i].Version == version {
			return &c.Releases[i]
		}
	}
	return nil
}

// GetCatalog fetches a catalog and its releases. Public route; no bearer.
// A 404 wraps ErrCatalogNotFound and a 410 wraps ErrCatalogTombstoned.
func (c *Client) GetCatalog(ctx context.Context, namespace, catalogID string) (*Catalog, error) {
	if namespace == "" || catalogID == "" {
		return nil, errors.New("namespace and catalog id are required")
	}
	path := fmt.Sprintf("/v1/catalogs/%s/%s", neturl.PathEscape(namespace), neturl.PathEscape(catalogID))
	status, body, err := c.do(ctx, http.MethodGet, path, nil, false)
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusOK:
		var out Catalog
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, fmt.Errorf("decoding catalog %s/%s: %w", namespace, catalogID, err)
		}
		return &out, nil
	case http.StatusNotFound:
		return nil, fmt.Errorf("%w: %s/%s", ErrCatalogNotFound, namespace, catalogID)
	case http.StatusGone:
		return nil, fmt.Errorf("%w: %s/%s", ErrCatalogTombstoned, namespace, catalogID)
	default:
		return nil, c.statusErr("catalog lookup", path, status, body)
	}
}
