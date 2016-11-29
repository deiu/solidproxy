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
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/labstack/echo"
)

var (
	agentWebID  string
	agentClient *http.Client
	agentCert   *tls.Certificate
	privKey     *rsa.PrivateKey

	exponentValue string
	modulusValue  string

	err error

	subjectAltName = []int{2, 5, 29, 17}
	notBefore      = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter       = time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC)
	rsaBits        = 2048
)

func InitAgentWebID(conf *ServerConfig) {
	// Create a new keypair
	privKey, err = rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		Logger.Panic(err)
		panic("Could not create keypair")
	}
	exponentValue = fmt.Sprintf("%d", privKey.PublicKey.E)
	modulusValue = fmt.Sprintf("%x", privKey.PublicKey.N)

	agentCert, err = NewRSAcert(conf.Agent, "Solid Proxy Agent", privKey)

	agentClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{*agentCert},
				InsecureSkipVerify: true,
			},
		},
	}
}

// WebIDHandler uses a closure with the signature func(http.ResponseWriter,
// *http.Request). It sets extra headers that are needed for serving the
// agent's WebID profile document
func WebIDHandler(c echo.Context) error {
	Logger.Printf("New request for agent WebID from: %+v\n", c.Request().RemoteAddr)
	// Do not return content
	profileTemplate := `@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
<>
    a <http://xmlns.com/foaf/0.1/PersonalProfileDocument> ;
    <http://xmlns.com/foaf/0.1/primaryTopic> <#me> .

<#me>
    a <http://xmlns.com/foaf/0.1/Agent> ;
    <http://www.w3.org/ns/auth/cert#key> <#key> .

<#key>
    a <http://www.w3.org/ns/auth/cert#RSAPublicKey> ;
    <http://www.w3.org/ns/auth/cert#exponent> "` + exponentValue + `"^^<http://www.w3.org/2001/XMLSchema#int> ;
    <http://www.w3.org/ns/auth/cert#modulus> "` + modulusValue + `"^^<http://www.w3.org/2001/XMLSchema#hexBinary> .
`
	return c.String(http.StatusOK, profileTemplate)
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
