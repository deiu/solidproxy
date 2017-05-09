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

	dsaPriv := []byte(`-----BEGIN DSA PRIVATE KEY-----
MIIBugIBAAKBgQCFTFUQWTgWhHBq5XLVQxf9mGNT7sqpqkv7rIA6E0aPy5odjTQA
cfqUqsHNttB49D5QmnFRy/PnSMTQAED8g9wmoTpC9XzxxTLTi+kwlAqi+QVg9Nf3
at1JOCdB8rxs+fo0ZmIoxcCFzhu0Rj6gNBt0BGm8Zbf3+CLZifpEPrR6cQIVANxm
WDNNSyy3sZRnHczwco2C705nAoGAcFPgrax5XjvuBVW3ivvn8E2VarwyFynqddAB
0UppC/7aRraUsBDs1m75KpMFjZOeXJJdiYsdTPqTDhorYJxFJNNOgm5fsXVxQV/i
wmpVOz2nZwdYP7jKa4Ac9VepnHwGb9XfSPSzudhXOIBNPWTURFYxB9OkI9WGPeYy
b01E6LcCgYAxCP29/tLDPjWFvZ69JamAkSqmGuCbAfbNJBIzPRocSb2h+9o15T66
ir6x/EQSr9bTtuq/C2oUNqYsZLfEgz4mJs5DICsO/eHinFojtFXK4l2gx7gvBCj7
kb+15cKkEdR2Y2ExGMME5oGwR8rzLS4e/Rektm7qInSvwpRpXYJ9FgIUP3MfsD46
UAUi/vfPLqHFncZe5pM=
-----END DSA PRIVATE KEY-----`)

	dsaPub := []byte(`-----BEGIN PUBLIC DSA KEY-----
MIIBtjCCASsGByqGSM44BAEwggEeAoGBAIVMVRBZOBaEcGrlctVDF/2YY1Puyqmq
S/usgDoTRo/Lmh2NNABx+pSqwc220Hj0PlCacVHL8+dIxNAAQPyD3CahOkL1fPHF
MtOL6TCUCqL5BWD01/dq3Uk4J0HyvGz5+jRmYijFwIXOG7RGPqA0G3QEabxlt/f4
ItmJ+kQ+tHpxAhUA3GZYM01LLLexlGcdzPByjYLvTmcCgYBwU+CtrHleO+4FVbeK
++fwTZVqvDIXKep10AHRSmkL/tpGtpSwEOzWbvkqkwWNk55ckl2Jix1M+pMOGitg
nEUk006Cbl+xdXFBX+LCalU7PadnB1g/uMprgBz1V6mcfAZv1d9I9LO52Fc4gE09
ZNREVjEH06Qj1YY95jJvTUTotwOBhAACgYAxCP29/tLDPjWFvZ69JamAkSqmGuCb
AfbNJBIzPRocSb2h+9o15T66ir6x/EQSr9bTtuq/C2oUNqYsZLfEgz4mJs5DICsO
/eHinFojtFXK4l2gx7gvBCj7kb+15cKkEdR2Y2ExGMME5oGwR8rzLS4e/Rektm7q
InSvwpRpXYJ9Fg==
-----END PUBLIC DSA KEY-----`)

	toSign := "some string"
	claim := sha1.Sum([]byte(toSign))

	_, err = ParseRSAPublicPEMKey(dsaPub)
	assert.Error(t, err)

	_, err := ParseRSAPrivatePEMKey(dsaPriv)
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
