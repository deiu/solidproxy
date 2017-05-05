package solidproxy

import (
	"crypto/sha1"
	"encoding/base64"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	testPrivKey []byte
	testPubKey  []byte
)

func init() {
	// load pub key from file
	f, err := os.Open("test_cert.pem")
	if err != nil {
		panic(err.Error())
	}
	f.Read(testPubKey)
	f.Close()

	// load priv key from file
	f, err = os.Open("test_key.pem")
	if err != nil {
		panic(err.Error())
	}
	f.Read(testPrivKey)
	f.Close()
}

func TestSignaturesRSA(t *testing.T) {
	privKey := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F
UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB
AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA
QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK
kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg
f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u
412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc
mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7
kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA
gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW
G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI
7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==
-----END RSA PRIVATE KEY-----`)

	pubKey := []byte(`-----BEGIN RSA PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
oYi+1hqp1fIekaxsyQIDAQAB
-----END RSA PUBLIC KEY-----`)

	h := `WebID-RSA source="https://deiu.me/Private/", username="https://deiu.me/profile#me", nonce="MTQzODc4MzA5NXxtS1dYcVd4bGRjVXQ2bFVEMXk2NE5KMDU1TFB3Nk9qM2FmMWduMk4tdl9tWDdvZXBtdUJSa1ZMRHE4WWZ1dUE0RlNGeDl0OGt6SGZnbkpZbW5CWE96TUxRamJ6a3xCC-Ik7gERpCBc__l2OK0DxVxyIiLTDVZ7rLIib2MNSQ==", sig="qiTKnXaXgMfGEA2LLCqhFWiB+6T9gXvLR6nO2dCvk71nBoK3MiwLxbsF83uKT81ur9SucDJ2fmjLKPbP9o7NrkYrM45rkPJsXHjbAzHDw2DftKLez5DF70HtDa1rEaUEF1mLrNMGfL4VYea5z15lNNNiDKaJpCwhgeHNB1x2qNY="`
	_toSign := `https://deiu.me/Private/https://deiu.me/profile#meMTQzODc4MzA5NXxtS1dYcVd4bGRjVXQ2bFVEMXk2NE5KMDU1TFB3Nk9qM2FmMWduMk4tdl9tWDdvZXBtdUJSa1ZMRHE4WWZ1dUE0RlNGeDl0OGt6SGZnbkpZbW5CWE96TUxRamJ6a3xCC-Ik7gERpCBc__l2OK0DxVxyIiLTDVZ7rLIib2MNSQ==`
	_sig := `qiTKnXaXgMfGEA2LLCqhFWiB+6T9gXvLR6nO2dCvk71nBoK3MiwLxbsF83uKT81ur9SucDJ2fmjLKPbP9o7NrkYrM45rkPJsXHjbAzHDw2DftKLez5DF70HtDa1rEaUEF1mLrNMGfL4VYea5z15lNNNiDKaJpCwhgeHNB1x2qNY=`
	p, err := parseRSAAuthorizationHeader(h)
	assert.NoError(t, err)

	assert.Equal(t, _sig, p.Signature)

	parser, perr := ParseRSAPublicPEMKey(pubKey)
	assert.NoError(t, perr)

	signer, err := ParseRSAPrivatePEMKey(privKey)
	assert.NoError(t, err)

	toSign := p.Source + p.Username + p.Nonce
	assert.Equal(t, _toSign, toSign)

	claim := sha1.Sum([]byte(toSign))
	signed, err := signer.Sign(claim[:])
	assert.NoError(t, err)
	b64Sig := base64.StdEncoding.EncodeToString(signed)
	assert.Equal(t, p.Signature, b64Sig)

	// println(p.Source, p.Username, p.Nonce, p.Signature)
	sig, err := base64.StdEncoding.DecodeString(p.Signature)
	assert.NoError(t, err)

	err = parser.Verify(claim[:], sig)
	assert.NoError(t, err)

	sig, err = base64.StdEncoding.DecodeString(_sig)
	assert.NoError(t, err)

	err = parser.Verify(claim[:], sig)
	assert.NoError(t, err)

	err = parser.Verify(claim[:], sig)
	assert.NoError(t, err)
}

func TestSignAndVerify(t *testing.T) {
	privKey := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F
UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB
AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA
QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK
kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg
f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u
412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc
mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7
kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA
gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW
G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI
7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==
-----END RSA PRIVATE KEY-----`)
	pubKey := []byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
oYi+1hqp1fIekaxsyQIDAQAB
-----END PUBLIC KEY-----`)

	toSign := "some string"
	claim := sha1.Sum([]byte(toSign))

	_, err := ParseRSAPrivatePEMKey([]byte("test"))
	assert.Error(t, err)

	_, err = ParseRSAPrivatePEMKey([]byte(`-----BEGIN RSA PRIVATE KEY-----
q28hxA161QFNUd13wuCTUcq0Qd2qsBe
-----END RSA PRIVATE KEY-----`))
	assert.Error(t, err)

	signer, err := ParseRSAPrivatePEMKey(privKey)
	assert.NoError(t, err)

	signed, err := signer.Sign(claim[:])
	assert.NoError(t, err)

	sig := base64.URLEncoding.EncodeToString(signed)
	assert.NotEmpty(t, sig)

	parser, perr := ParseRSAPublicPEMKey(pubKey)
	assert.NoError(t, perr)

	err = parser.Verify(claim[:], signed)
	assert.NoError(t, err)
}
