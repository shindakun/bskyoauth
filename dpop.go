package bskyoauth

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

// dpopTransport is an HTTP transport that automatically adds DPoP headers to requests.
type dpopTransport struct {
	underlying http.RoundTripper
	dpopKey    *ecdsa.PrivateKey
	token      string
	nonce      string
	mu         sync.Mutex
}

// NewDPoPTransport creates a new HTTP transport with DPoP support.
func NewDPoPTransport(underlying http.RoundTripper, dpopKey *ecdsa.PrivateKey, token string) http.RoundTripper {
	if underlying == nil {
		underlying = http.DefaultTransport
	}
	return &dpopTransport{
		underlying: underlying,
		dpopKey:    dpopKey,
		token:      token,
	}
}

// RoundTrip implements http.RoundTripper with DPoP proof generation and nonce handling.
func (t *dpopTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	currentNonce := t.nonce
	t.mu.Unlock()

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
		// Check for use_dpop_nonce error
		if newNonce := resp.Header.Get("DPoP-Nonce"); newNonce != "" {
			// Read the body to check for nonce error
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			bodyStr := string(bodyBytes)
			if strings.Contains(bodyStr, "use_dpop_nonce") || strings.Contains(bodyStr, "nonce") {
				// Update nonce and retry
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
				retryReq := req.Clone(req.Context())
				retryReq.Header.Set("DPoP", dpopProof)
				retryReq.Header.Set("Authorization", "DPoP "+t.token)

				// Retry the request
				resp, err = t.underlying.RoundTrip(retryReq)
				if err != nil {
					return nil, err
				}
			} else {
				// Restore the body for non-nonce errors
				resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}
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

// createDPoPProof creates a DPoP JWT proof for the given request.
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

// generateRandomString generates a cryptographically secure random string.
func generateRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)[:length]
}

// generateUniqueJTI generates a unique JWT ID for DPoP proofs using timestamp and random bytes.
// This prevents replay attacks by ensuring each proof has a unique identifier.
func generateUniqueJTI() string {
	// Use nanosecond timestamp for better uniqueness
	timestamp := time.Now().UnixNano()
	// Generate 16 bytes of random data
	randomBytes := make([]byte, 16)
	rand.Read(randomBytes)
	// Combine timestamp and random bytes
	combined := append([]byte(base64.RawURLEncoding.EncodeToString([]byte{
		byte(timestamp >> 56), byte(timestamp >> 48), byte(timestamp >> 40), byte(timestamp >> 32),
		byte(timestamp >> 24), byte(timestamp >> 16), byte(timestamp >> 8), byte(timestamp),
	})), randomBytes...)
	return base64.RawURLEncoding.EncodeToString(combined)
}
