package solidproxy

import (
	"crypto/tls"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	testProxyServer *httptest.Server
	testAgentServer *httptest.Server
	testClient      *http.Client
)

func init() {
	debug := false
	enableLogger := ioutil.Discard
	if debug {
		enableLogger = os.Stderr
	}
	Logger = log.New(enableLogger, "[debug] ", log.Flags()|log.Lshortfile)

	// ** PROXY **
	proxyConf := NewServerConfig()
	proxyConf.InsecureSkipVerify = true
	proxyConf.User = "https://alice.com/webid#me"
	proxyServer := NewProxyServer(proxyConf)

	// testProxyServer
	testProxyServer = httptest.NewServer(proxyServer)
	testProxyServer.URL = strings.Replace(testProxyServer.URL, "127.0.0.1", "localhost", 1)

	// ** AGENT **
	agentConf := NewServerConfig()
	agentConf.TLSKey = "test_key.pem"
	agentConf.TLSCert = "test_cert.pem"
	agentConf.Agent = "https://agent.com/webid#me"
	agentConf.User = "https://alice.com/webid#me"
	agentServer := NewAgentServer(agentConf)
	// testProxyServer
	testAgentServer = httptest.NewUnstartedServer(agentServer)
	testAgentServer.TLS = new(tls.Config)
	testAgentServer.TLS.MinVersion = tls.VersionTLS12
	testAgentServer.TLS.NextProtos = []string{"h2"}
	// use strong crypto
	testAgentServer.TLS.PreferServerCipherSuites = true
	testAgentServer.TLS.CurvePreferences = []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256}
	testAgentServer.TLS.CipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	}
	testAgentServer.TLS.Certificates = make([]tls.Certificate, 1)
	testAgentServer.TLS.Certificates[0], err = tls.LoadX509KeyPair(agentConf.TLSCert, agentConf.TLSKey)
	testAgentServer.StartTLS()
	testAgentServer.URL = strings.Replace(testAgentServer.URL, "127.0.0.1", "localhost", 1)

	// ** CLIENT **
	// testClient
	testClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
}

func TestServerVersion(t *testing.T) {
	assert.NotEmpty(t, GetVersion())
}

func TestRouteNotImplemented(t *testing.T) {
	req, err := http.NewRequest("GET", testAgentServer.URL, nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 501, resp.StatusCode)

	req, err = http.NewRequest("GET", testProxyServer.URL, nil)
	assert.NoError(t, err)
	resp, err = testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 501, resp.StatusCode)
}

func TestRouteWebID(t *testing.T) {
	req, err := http.NewRequest("GET", testAgentServer.URL+"/webid", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "text/turtle", resp.Header.Get("Content-Type"))
}

func TestRouteProxyWithURI(t *testing.T) {
	req, err := http.NewRequest("GET", testProxyServer.URL+"/proxy?uri="+testAgentServer.URL+"/webid", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}

func TestRouteProxyNoURI(t *testing.T) {
	req, err := http.NewRequest("GET", testProxyServer.URL+"/proxy", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 500, resp.StatusCode)
}

func TestRouteProxyEmptyURI(t *testing.T) {
	req, err := http.NewRequest("GET", testProxyServer.URL+"/proxy?uri=", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 500, resp.StatusCode)
}
