package oauth

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/shindakun/bskyoauth/internal/dpop"
)

// TokenExchanger handles OAuth token operations
type TokenExchanger struct {
	ClientID     string
	RedirectURI  string
	HTTPClient   *http.Client
	LoggerGetter func(context.Context) Logger
}

// Logger interface for token operations
type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}

// RefreshTokenRequest performs the refresh token exchange with DPoP.
func (t *TokenExchanger) RefreshTokenRequest(ctx context.Context, tokenEndpoint, refreshToken string, dpopKey interface{}, currentNonce string) (map[string]interface{}, error) {
	logger := t.LoggerGetter(ctx)

	// Create DPoP proof for refresh request
	dpopProof, err := dpop.CreateDPoPProof(dpopKey.(*ecdsa.PrivateKey), "POST", tokenEndpoint, "", currentNonce)
	if err != nil {
		return nil, err
	}

	// Build refresh token request
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", t.ClientID)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", dpopProof)

	resp, err := t.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// Handle DPoP nonce retry (same as token exchange)
	if resp.StatusCode == http.StatusBadRequest {
		var errorResp map[string]interface{}
		if err := json.Unmarshal(body, &errorResp); err == nil {
			if errorResp["error"] == "use_dpop_nonce" {
				nonce := resp.Header.Get("DPoP-Nonce")
				if nonce != "" {
					logger.Info("retrying token refresh with DPoP nonce",
						"token_endpoint", tokenEndpoint)

					// Retry with nonce
					dpopProof, err = dpop.CreateDPoPProof(dpopKey.(*ecdsa.PrivateKey), "POST", tokenEndpoint, "", nonce)
					if err != nil {
						return nil, err
					}

					req, err = http.NewRequestWithContext(ctx, "POST", tokenEndpoint, strings.NewReader(data.Encode()))
					if err != nil {
						return nil, fmt.Errorf("failed to create retry refresh token request: %w", err)
					}
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					req.Header.Set("DPoP", dpopProof)

					resp, err = t.HTTPClient.Do(req)
					if err != nil {
						return nil, err
					}
					defer resp.Body.Close()

					body, _ = io.ReadAll(resp.Body)
				}
			}
		}
	}

	if resp.StatusCode != http.StatusOK {
		logger.Error("token refresh request failed",
			"token_endpoint", tokenEndpoint,
			"status", resp.Status,
			"body", string(body))
		return nil, fmt.Errorf("token refresh failed (status: %d)", resp.StatusCode)
	}

	var tokens map[string]interface{}
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, err
	}

	return tokens, nil
}

// ExchangeCodeForTokens exchanges an authorization code for access and refresh tokens.
func (t *TokenExchanger) ExchangeCodeForTokens(ctx context.Context, tokenEndpoint, code, codeVerifier string, dpopKey interface{}) (map[string]interface{}, error) {
	logger := t.LoggerGetter(ctx)
	// First attempt without nonce to get the nonce
	dpopProof, err := dpop.CreateDPoPProof(dpopKey.(*ecdsa.PrivateKey), "POST", tokenEndpoint, "", "")
	if err != nil {
		return nil, err
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", t.RedirectURI)
	data.Set("client_id", t.ClientID)
	data.Set("code_verifier", codeVerifier)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", dpopProof)

	resp, err := t.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// Check if we need to retry with nonce
	if resp.StatusCode == http.StatusBadRequest {
		var errorResp map[string]interface{}
		if err := json.Unmarshal(body, &errorResp); err == nil {
			if errorResp["error"] == "use_dpop_nonce" {
				// Get nonce from header and retry
				nonce := resp.Header.Get("DPoP-Nonce")
				if nonce != "" {
					logger.Info("retrying token exchange with DPoP nonce",
						"token_endpoint", tokenEndpoint)
					// Retry with nonce
					dpopProof, err = dpop.CreateDPoPProof(dpopKey.(*ecdsa.PrivateKey), "POST", tokenEndpoint, "", nonce)
					if err != nil {
						return nil, err
					}

					req, err = http.NewRequestWithContext(ctx, "POST", tokenEndpoint, strings.NewReader(data.Encode()))
					if err != nil {
						return nil, fmt.Errorf("failed to create retry token exchange request: %w", err)
					}
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					req.Header.Set("DPoP", dpopProof)

					resp, err = t.HTTPClient.Do(req)
					if err != nil {
						return nil, err
					}
					defer resp.Body.Close()

					body, _ = io.ReadAll(resp.Body)
				}
			}
		}
	}

	if resp.StatusCode != http.StatusOK {
		// Log detailed error internally for debugging/monitoring
		logger.Error("token exchange failed",
			"token_endpoint", tokenEndpoint,
			"status", resp.Status,
			"body", string(body))
		// Return generic error to user to prevent information disclosure
		return nil, fmt.Errorf("token exchange failed (status: %d)", resp.StatusCode)
	}

	var tokens map[string]interface{}
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, err
	}

	return tokens, nil
}

// ParseTokenExpiration parses expiration time from token response
func ParseTokenExpiration(tokens map[string]interface{}, key string) (time.Time, bool) {
	if expiresIn, ok := tokens[key].(float64); ok {
		return time.Now().Add(time.Duration(expiresIn) * time.Second), true
	}
	return time.Time{}, false
}

// ValidateRefreshToken validates that a refresh token is present and not expired
func ValidateRefreshToken(refreshToken string, expiresAt time.Time) error {
	if refreshToken == "" {
		return errors.New("no refresh token available")
	}

	if !expiresAt.IsZero() && time.Now().After(expiresAt) {
		return errors.New("refresh token expired")
	}

	return nil
}
