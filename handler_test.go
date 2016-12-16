package solidproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	testProxyServerS *httptest.Server
	testProxyServer  *httptest.Server
	testAgentServer  *httptest.Server
	testClient       *http.Client
	testAgentWebID   string
)

func init() {
	var err error
	skipVerify := true

	testAgentWebID = "https://example.com/webid#me"

	// ** AGENT **
	agent, err := NewAgent(testAgentWebID)
	if err != nil {
		panic(err)
	}
	agentConf := NewServerConfig()
	agentConf.TLSKey = "test_key.pem"
	agentConf.TLSCert = "test_cert.pem"
	agentConf.Agent = testAgentWebID
	agentServer := NewAgentHandler(agentConf, agent)
	// testProxyServer
	testAgentServer = httptest.NewUnstartedServer(agentServer)
	testAgentServer.TLS, err = NewTLSConfig(agentConf)
	if err != nil {
		panic(err)
	}
	testAgentServer.StartTLS()
	testAgentServer.URL = strings.Replace(testAgentServer.URL, "127.0.0.1", "localhost", 1)

	// ** PROXY **
	proxy := NewProxy(agent, skipVerify)
	proxyConf := NewServerConfig()
	proxyConf.InsecureSkipVerify = skipVerify
	proxyConf.Agent = testAgentWebID
	proxyServer := NewProxyHandler(proxyConf, proxy)

	// testProxyServer
	testProxyServer = httptest.NewServer(proxyServer)
	testProxyServer.URL = strings.Replace(testProxyServer.URL, "127.0.0.1", "localhost", 1)

	// ** CLIENT **
	// testClient
	testClient = NewClient(proxyConf.InsecureSkipVerify)
}

func TestServerVersion(t *testing.T) {
	assert.Equal(t, SERVER_VERSION, GetVersion())
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

func TestRouteProxyNoURIParam(t *testing.T) {
	req, err := http.NewRequest("GET", testProxyServer.URL+"/proxy", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

func TestRouteProxyEmptyURIValue(t *testing.T) {
	req, err := http.NewRequest("GET", testProxyServer.URL+"/proxy?uri=", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

func TestLogger(t *testing.T) {
	config := NewServerConfig()
	config.Verbose = true
	logger := InitLogger(config)
	assert.NotNil(t, logger)
}
