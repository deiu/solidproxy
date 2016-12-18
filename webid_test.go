package solidproxy

import (
	"crypto/rsa"
	"fmt"

	// "net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

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

func TestNewRSAcert(t *testing.T) {
	p, _, _, err := NewRSAKey(rsaBits)
	assert.NoError(t, err)
	cert, err := NewRSAcert(testAgentWebID, "Solid Proxy Agent", p)
	assert.NoError(t, err)

	webid, err := WebIDFromCert(cert)
	assert.NoError(t, err)
	assert.Equal(t, testAgentWebID, webid)
}
