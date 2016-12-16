package solidproxy

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	// "net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRSAKey(t *testing.T) {
	p, e, n, err := NewRSAKey()
	assert.NoError(t, err)
	assert.IsType(t, new(rsa.PrivateKey), p)
	assert.Equal(t, fmt.Sprintf("%d", p.PublicKey.E), e)
	assert.NotEmpty(t, fmt.Sprintf("%x", p.PublicKey.N), n)
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

func TestNewRSAcert(t *testing.T) {
	p, _, _, err := NewRSAKey()
	assert.NoError(t, err)
	cert, err := NewRSAcert(testAgentWebID, "Solid Proxy Agent", p)
	assert.NoError(t, err)

	webid, err := WebIDFromCert(cert.Certificate[0])
	assert.NoError(t, err)
	assert.Equal(t, "URI: "+testAgentWebID, webid)
}

func WebIDFromCert(cert []byte) (string, error) {
	parsed, err := x509.ParseCertificate(cert)
	if err != nil {
		return "", err
	}

	for _, x := range parsed.Extensions {
		if x.Id.Equal(subjectAltName) {
			v := asn1.RawValue{}
			_, err = asn1.Unmarshal(x.Value, &v)
			if err != nil {
				return "", err
			}
			return string(v.Bytes[2:]), nil
		}
	}
	return "", nil
}
