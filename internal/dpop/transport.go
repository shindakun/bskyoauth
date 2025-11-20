package dpop

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Transport is an HTTP transport that automatically adds DPoP headers to requests.
type Transport struct {
	underlying http.RoundTripper
	dpopKey    *ecdsa.PrivateKey
	token      string
	nonce      string
	mu         sync.Mutex
}

// NewTransport creates a new HTTP transport with DPoP support.
// The nonce parameter allows reusing a previously obtained nonce to avoid replay errors.
func NewTransport(underlying http.RoundTripper, dpopKey *ecdsa.PrivateKey, token string, nonce string) http.RoundTripper {
	if underlying == nil {
		underlying = http.DefaultTransport
	}
	return &Transport{
		underlying: underlying,
		dpopKey:    dpopKey,
		token:      token,
		nonce:      nonce,
	}
}

// GetNonce returns the current DPoP nonce.
func (t *Transport) GetNonce() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.nonce
}

// RoundTrip implements http.RoundTripper with DPoP proof generation and nonce handling.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	currentNonce := t.nonce
	t.mu.Unlock()

	// Preserve request body for potential retry
	// We need to buffer the body so it can be re-read if we need to retry
	var bodyBytes []byte
	if req.Body != nil && req.Body != http.NoBody {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body.Close()

		// Restore body for the first request
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		req.ContentLength = int64(len(bodyBytes))

		// Set GetBody so req.Clone() can recreate the body for retries
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewBuffer(bodyBytes)), nil
		}
	}

	// Create DPoP proof for this request
	dpopProof, err := createDPoPProof(t.dpopKey, req.Method, req.URL.String(), t.token, currentNonce)
	if err != nil {
		return nil, err
	}

	req.Header.Set("DPoP", dpopProof)
	req.Header.Set("Authorization", "DPoP "+t.token)

	resp, err := t.underlying.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// Check if we need to retry with nonce
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusBadRequest {
		// Read the body to check for DPoP errors
		respBodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		bodyStr := string(respBodyBytes)

		// Check for DPoP-related errors that require a fresh nonce
		isDPoPError := strings.Contains(bodyStr, "use_dpop_nonce") ||
			strings.Contains(bodyStr, "nonce") ||
			strings.Contains(bodyStr, "replayed") ||
			strings.Contains(bodyStr, "invalid_dpop_proof")

		if isDPoPError {
			// Check if server provided a new nonce
			if newNonce := resp.Header.Get("DPoP-Nonce"); newNonce != "" {
				// Update nonce and retry with fresh proof
				t.mu.Lock()
				t.nonce = newNonce
				currentNonce = newNonce
				t.mu.Unlock()

				// Create new DPoP proof with nonce
				dpopProof, err = createDPoPProof(t.dpopKey, req.Method, req.URL.String(), t.token, currentNonce)
				if err != nil {
					return nil, err
				}

				// Clone the request for retry
				// Manually create a fresh request with a new body reader
				retryReq := req.Clone(req.Context())
				if len(bodyBytes) > 0 {
					retryReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
					retryReq.ContentLength = int64(len(bodyBytes))
					retryReq.GetBody = func() (io.ReadCloser, error) {
						return io.NopCloser(bytes.NewReader(bodyBytes)), nil
					}
				}
				retryReq.Header.Set("DPoP", dpopProof)
				retryReq.Header.Set("Authorization", "DPoP "+t.token)

				// Retry the request
				resp, err = t.underlying.RoundTrip(retryReq)
				if err != nil {
					return nil, err
				}
			} else {
				// DPoP error but no nonce provided - restore body and return error
				resp.Body = io.NopCloser(bytes.NewBuffer(respBodyBytes))
			}
		} else {
			// Restore the body for non-DPoP errors
			resp.Body = io.NopCloser(bytes.NewBuffer(respBodyBytes))
		}
	}

	// Update nonce if provided in response
	if resp != nil {
		if newNonce := resp.Header.Get("DPoP-Nonce"); newNonce != "" {
			t.mu.Lock()
			t.nonce = newNonce
			t.mu.Unlock()
		}
	}

	return resp, err
}

// CreateDPoPProof creates a DPoP JWT proof for the given request.
// This is exported for use by other packages in the library.
func CreateDPoPProof(key *ecdsa.PrivateKey, method, uri, accessToken, nonce string) (string, error) {
	return createDPoPProof(key, method, uri, accessToken, nonce)
}

// createDPoPProof creates a DPoP JWT proof for the given request (internal).
func createDPoPProof(key *ecdsa.PrivateKey, method, uri, accessToken, nonce string) (string, error) {
	now := time.Now().Unix()
	// Generate unique JTI with timestamp and random bytes for better uniqueness
	jti := generateUniqueJTI()

	parsedURL, _ := url.Parse(uri)
	htm := method
	htu := parsedURL.Scheme + "://" + parsedURL.Host + parsedURL.Path

	// Create JWK representation of public key
	jwkMap := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes()),
	}

	claims := jwt.MapClaims{
		"htm": htm,
		"htu": htu,
		"jti": jti,
		"iat": now,
	}

	if nonce != "" {
		claims["nonce"] = nonce
	}

	if accessToken != "" {
		hash := sha256.Sum256([]byte(accessToken))
		ath := base64.RawURLEncoding.EncodeToString(hash[:])
		claims["ath"] = ath
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = jwkMap

	signedToken, err := token.SignedString(key)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// GenerateDPoPKey generates a new ECDSA P-256 key pair for DPoP.
func GenerateDPoPKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// GenerateRandomString generates a cryptographically secure random string.
// This is exported for use by other packages in the library.
func GenerateRandomString(length int) string {
	return generateRandomString(length)
}

// generateRandomString generates a cryptographically secure random string (internal).
func generateRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)[:length]
}

// generateUniqueJTI generates a unique JWT ID for DPoP proofs using timestamp and random bytes.
// This prevents replay attacks by ensuring each proof has a unique identifier.
func generateUniqueJTI() string {
	// Generate 24 bytes of cryptographically secure random data
	// This provides 192 bits of entropy, making collisions astronomically unlikely
	randomBytes := make([]byte, 24)
	rand.Read(randomBytes)
	return base64.RawURLEncoding.EncodeToString(randomBytes)
}
