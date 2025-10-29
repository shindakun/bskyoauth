package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// AuthServerMetadata contains OAuth authorization server metadata.
type AuthServerMetadata struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	Issuer                string `json:"issuer"`
	JWKSURI               string `json:"jwks_uri"`
}

// MetadataFetcher handles fetching OAuth server metadata
type MetadataFetcher struct {
	HTTPClient     *http.Client
	LoggerGetter   func(context.Context) Logger
	IsTimeoutError func(error) bool
}

// FetchAuthServerMetadata fetches OAuth authorization server metadata from a PDS
func (m *MetadataFetcher) FetchAuthServerMetadata(ctx context.Context, authServer string) (*AuthServerMetadata, error) {
	logger := m.LoggerGetter(ctx)
	metadataURL := authServer + "/.well-known/oauth-authorization-server"

	req, err := http.NewRequestWithContext(ctx, "GET", metadataURL, nil)
	if err != nil {
		logger.Error("failed to create metadata request",
			"url", metadataURL,
			"error", err)
		return nil, fmt.Errorf("failed to create metadata request: %w", err)
	}

	resp, err := m.HTTPClient.Do(req)
	if err != nil {
		if m.IsTimeoutError(err) {
			logger.Error("auth server metadata request timeout",
				"url", metadataURL,
				"error", err)
		} else {
			logger.Error("failed to get auth server metadata",
				"url", metadataURL,
				"error", err)
		}
		return nil, fmt.Errorf("failed to get auth server metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Error("auth server metadata request failed",
			"status", resp.Status,
			"url", metadataURL)
		return nil, fmt.Errorf("metadata request failed with status: %s", resp.Status)
	}

	var metadata AuthServerMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		logger.Error("failed to decode auth server metadata",
			"url", metadataURL,
			"error", err)
		return nil, fmt.Errorf("failed to decode metadata: %w", err)
	}

	return &metadata, nil
}
