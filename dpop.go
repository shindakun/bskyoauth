package bskyoauth

import (
	"crypto/ecdsa"
	"net/http"

	"github.com/shindakun/bskyoauth/internal/dpop"
)

// DPoPTransport is an interface for transports that support DPoP nonce management.
// This allows accessing the current nonce without needing to know the concrete type.
type DPoPTransport interface {
	http.RoundTripper
	GetNonce() string
}

// NewDPoPTransport creates a new HTTP transport with DPoP support.
// The nonce parameter allows reusing a previously obtained nonce to avoid replay errors.
// This is a wrapper around internal/dpop.NewTransport to maintain backward compatibility.
func NewDPoPTransport(underlying http.RoundTripper, dpopKey *ecdsa.PrivateKey, token string, nonce string) http.RoundTripper {
	return dpop.NewTransport(underlying, dpopKey, token, nonce)
}

// GenerateDPoPKey generates a new ECDSA P-256 key pair for DPoP.
// This is a wrapper around internal/dpop.GenerateDPoPKey to maintain backward compatibility.
func GenerateDPoPKey() (*ecdsa.PrivateKey, error) {
	return dpop.GenerateDPoPKey()
}
