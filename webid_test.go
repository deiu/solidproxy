package solidproxy

import (
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"net/http"

	// "net/http"
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
