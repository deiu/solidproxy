package solidproxy

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"
)

type Agent struct {
	WebID   string
	Profile string
	Cert    *tls.Certificate
	Key     *rsa.PrivateKey
	Log     *log.Logger
}

var (
	err            error
	subjectAltName = []int{2, 5, 29, 17}
	notBefore      = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter       = time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC)
	rsaBits        = 2048
)

func NewAgent(uri string) (*Agent, error) {
	agent := &Agent{}
	if len(uri) == 0 {
		return agent, errors.New("You must provide an URI for the agent's WebID")
	}
	agent.WebID = uri
	return agent, nil
}

func NewAgentLocal(uri string, bits ...int) (*Agent, error) {
	agent, err := NewAgent(uri)
	if err != nil {
		return agent, err
	}

	keyLen := rsaBits
	if len(bits) > 0 {
		keyLen = bits[0]
	}

	// Create a new keypair
	privKey, E, N, err := NewRSAKey(keyLen)
	if err != nil {
		return agent, err
	}
	agent.Key = privKey

	agent.Profile = NewAgentProfile(E, N)
	agent.Cert, err = NewRSAcert(uri, "Solid Agent", privKey)

	return agent, nil
}

func NewRSAKey(bits int) (*rsa.PrivateKey, string, string, error) {
	var e, n string
	p, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return p, e, n, err
	}
	e = fmt.Sprintf("%d", p.PublicKey.E)
	n = fmt.Sprintf("%x", p.PublicKey.N)

	return p, e, n, err
}

// Handler function handles requests for the agent's WebID profile document
func (agent *Agent) Handler(w http.ResponseWriter, req *http.Request) {
	agent.Log.Printf("New request for agent WebID from: %+v\n", req.RemoteAddr)
	w.Header().Set("Content-Type", "text/turtle")
	w.WriteHeader(200)
	w.Write([]byte(agent.Profile))
}

// NewAgentProfile returns a new WebID profile document for the agent
func NewAgentProfile(exp string, mod string) string {
	return `@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
<>
    a <http://xmlns.com/foaf/0.1/PersonalProfileDocument> ;
    <http://xmlns.com/foaf/0.1/primaryTopic> <#me> .

<#me>
    a <http://xmlns.com/foaf/0.1/Agent> ;
    <http://www.w3.org/ns/auth/cert#key> <#key> .

<#key>
    a <http://www.w3.org/ns/auth/cert#RSAPublicKey> ;
    <http://www.w3.org/ns/auth/cert#exponent> "` + exp + `"^^<http://www.w3.org/2001/XMLSchema#int> ;
    <http://www.w3.org/ns/auth/cert#modulus> "` + mod + `"^^<http://www.w3.org/2001/XMLSchema#hexBinary> .
`
}

// NewRSAcert creates a new RSA x509 self-signed certificate to use for
// WebID-TLS authentication
func NewRSAcert(uri string, name string, priv *rsa.PrivateKey) (*tls.Certificate, error) {
	// Create the certificate
	uri = "URI: " + uri
	template := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(42),
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{"WebID"},
			// Country:      []string{"US"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	rawValues := []asn1.RawValue{
		{Class: 2, Tag: 6, Bytes: []byte(uri)},
	}
	values, err := asn1.Marshal(rawValues)
	if err != nil {
		return nil, err
	}
	template.ExtraExtensions = []pkix.Extension{{Id: subjectAltName, Value: values}}

	keyPEM := bytes.NewBuffer(nil)
	err = pem.Encode(keyPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err != nil {
		return nil, err
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	certPEM := bytes.NewBuffer(nil)
	err = pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(certPEM.Bytes(), keyPEM.Bytes())
	if err != nil {
		return nil, err
	}

	return &cert, nil
}
