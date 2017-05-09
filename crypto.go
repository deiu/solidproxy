package solidproxy

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// Signer creates signatures that verify against a public key.
type Signer interface {
	Sign(data []byte) ([]byte, error)
}

// Verifier verifies signatures against a public key.
type Verifier interface {
	Verify(data []byte, sig []byte) error
}

type rsaPubKey struct {
	*rsa.PublicKey
}

type rsaPrivKey struct {
	*rsa.PrivateKey
}

// ParseRSAPublicPEMKey parses a PEM encoded private key and returns a new verifier object
func ParseRSAPublicPEMKey(pemBytes []byte) (Verifier, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("No key found")
	}

	var rawkey interface{}
	switch block.Type {
	case "RSA PUBLIC KEY", "PUBLIC KEY":
		rsa, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
	default:
		return nil, fmt.Errorf("Unsupported key type %q", block.Type)
	}

	return newVerifierFromKey(rawkey)
}

// ParseRSAPrivatePEMKey parses a PEM encoded private key and returns a Signer.
func ParseRSAPrivatePEMKey(pemBytes []byte) (Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("No key found or could not decode PEM key")
	}

	var rawkey interface{}
	switch block.Type {
	case "RSA PRIVATE KEY", "PRIVATE KEY":
		rsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
	default:
		return nil, fmt.Errorf("Unsupported key type %q", block.Type)
	}
	return newSignerFromKey(rawkey)
}

func newSignerFromKey(k interface{}) (Signer, error) {
	var sKey Signer
	switch t := k.(type) {
	case *rsa.PrivateKey:
		// we only support one type
		sKey = &rsaPrivKey{t}
	}
	return sKey, nil
}

func newVerifierFromKey(k interface{}) (Verifier, error) {
	var vKey Verifier
	switch t := k.(type) {
	case *rsa.PublicKey:
		// we only support one type
		vKey = &rsaPubKey{t}
	}
	return vKey, nil
}

// Sign signs data with rsa-sha256
func (r *rsaPrivKey) Sign(data []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, r.PrivateKey, crypto.SHA1, data)
}

// Verify verifies the message using a rsa-sha256 signature
func (r *rsaPubKey) Verify(message []byte, sig []byte) error {
	return rsa.VerifyPKCS1v15(r.PublicKey, crypto.SHA1, message, sig)
}
