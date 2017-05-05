package solidproxy

import (
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRSAcert(t *testing.T) {
	p, _, _, err := NewRSAKey(rsaBits)
	assert.NoError(t, err)
	cert, err := NewRSAcert(testAgentWebID, "Solid Proxy Agent", p)
	assert.NoError(t, err)

	webid, err := WebIDFromCert(cert)
	assert.NoError(t, err)
	assert.Equal(t, testAgentWebID, webid)

	webid, err = WebIDFromBytes(cert.Certificate[0])
	assert.NoError(t, err)
	assert.Equal(t, testAgentWebID, webid)
}

func TestNewRSAKey(t *testing.T) {
	p, e, n, err := NewRSAKey(rsaBits)
	assert.NoError(t, err)
	assert.IsType(t, new(rsa.PrivateKey), p)
	assert.Equal(t, fmt.Sprintf("%d", p.PublicKey.E), e)
	assert.NotEmpty(t, fmt.Sprintf("%x", p.PublicKey.N), n)
}

func TestNewRSAKeyError(t *testing.T) {
	_, _, _, err := NewRSAKey(0)
	assert.Error(t, err)
}

func TestNewAgent(t *testing.T) {
	agent, err := NewAgent(testAgentWebID)
	assert.NoError(t, err)
	assert.Equal(t, agent.WebID, testAgentWebID)
}

func TestNewAgentEmptyURI(t *testing.T) {
	agent, err := NewAgent("")
	assert.Error(t, err)
	assert.Empty(t, agent.WebID)
}

func TestNewAgentLocalEmptyURI(t *testing.T) {
	agent, err := NewAgentLocal("")
	assert.Error(t, err)
	assert.Empty(t, agent.WebID)
}

func TestNewAgentLocalBadKey(t *testing.T) {
	_, err := NewAgentLocal(testAgentWebID, 0)
	assert.Error(t, err)
}

func TestWebIDFromBytesFail(t *testing.T) {
	_, err := WebIDFromBytes([]byte(""))
	assert.Error(t, err)
}

func TestWebIDFromCertFail(t *testing.T) {
	crt := &tls.Certificate{}
	crt.Certificate = append(crt.Certificate, []byte(""))
	_, err := WebIDFromCert(crt)
	assert.Error(t, err)
}

func TestWebIDFromReqFail(t *testing.T) {
	req, err := http.NewRequest("HEAD", testAgentWebID, nil)
	assert.NoError(t, err)
	_, err = WebIDFromReq(req)
	assert.Error(t, err)

	req.TLS = &tls.ConnectionState{}
	req.TLS.HandshakeComplete = true
	_, err = WebIDFromReq(req)
	assert.Error(t, err)
}

func TestParseRSAAuthorizationHeader(t *testing.T) {
	_, err = parseRSAAuthorizationHeader("")
	assert.Error(t, err)

	h := "WebID-Other source=\"http://server.org/\""
	_, err = parseRSAAuthorizationHeader(h)
	assert.Error(t, err)

	h = "WebID-RSA source=\"http://server.org/\", username=\"http://example.org/\", nonce=\"string1\", sig=\"string2\""
	p, err := parseRSAAuthorizationHeader(h)
	assert.NoError(t, err)
	assert.Equal(t, "http://server.org/", p.Source)
	assert.Equal(t, "http://example.org/", p.Username)
	assert.Equal(t, "string1", p.Nonce)
	assert.Equal(t, "string2", p.Signature)

	h = "WebID-RSA source=\"http://server.org/\", \nusername=\"http://example.org/\", \nnonce=\"string1\",\n sig=\"string2\""
	p, err = parseRSAAuthorizationHeader(h)
	assert.NoError(t, err)
	assert.Equal(t, "http://server.org/", p.Source)
	assert.Equal(t, "http://example.org/", p.Username)
	assert.Equal(t, "string1", p.Nonce)
	assert.Equal(t, "string2", p.Signature)
}

func TestParseRSAAuthenticateHeader(t *testing.T) {
	_, err := ParseRSAAuthenticateHeader("")
	assert.Error(t, err)

	h := `WebID-Other source="http://server.org/"`
	_, err = ParseRSAAuthenticateHeader(h)
	assert.Error(t, err)

	h = `WebID-RSA source="http://server.org/", nonce="string1"`
	p, err := ParseRSAAuthenticateHeader(h)
	assert.NoError(t, err)
	assert.Equal(t, "string1", p.Nonce)
	assert.Equal(t, "http://server.org/", p.Source)

}

// parseRSAAuthorizationHeader is a helper function used for testing WebID-RSA auth
func parseRSAAuthorizationHeader(header string) (*RSAAuthorization, error) {
	auth := &RSAAuthorization{}

	if len(header) == 0 {
		return auth, errors.New("Cannot parse Authorization header: no header present")
	}

	opts := make(map[string]string)
	parts := strings.SplitN(header, " ", 2)
	if parts[0] != "WebID-RSA" {
		return auth, errors.New("Not a WebID-RSA authorization header. Got " + parts[0])
	}

	parts = strings.Split(parts[1], ",")

	for _, part := range parts {
		vals := strings.SplitN(strings.TrimSpace(part), "=", 2)
		key := vals[0]
		val := strings.Replace(vals[1], "\"", "", -1)
		opts[key] = val
	}

	auth = &RSAAuthorization{
		opts["source"],
		opts["username"],
		opts["nonce"],
		opts["sig"],
	}
	return auth, nil
}
