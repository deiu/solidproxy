package solidproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	testServer *httptest.Server
	testClient *http.Client
)

func init() {
	conf := NewServerConfig()
	conf.Verbose = false
	conf.Insecure = true
	conf.User = "https://alice.com/webid#me"
	e := NewServer(conf)

	// testServer
	testServer = httptest.NewServer(e)
	testServer.URL = strings.Replace(testServer.URL, "127.0.0.1", "localhost", 1)
	// testClient
	testClient = &http.Client{}
}

func TestServerVersion(t *testing.T) {
	assert.NotEmpty(t, GetVersion())
}

func TestRouteNotImplemented(t *testing.T) {
	req, err := http.NewRequest("GET", testServer.URL, nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 501, resp.StatusCode)
}

func TestRouteWebID(t *testing.T) {
	req, err := http.NewRequest("GET", testServer.URL+"/webid", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}

func TestRouteProxyWithURI(t *testing.T) {
	req, err := http.NewRequest("GET", testServer.URL+"/proxy?uri="+testServer.URL+"/webid", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}

func TestRouteProxyNoURI(t *testing.T) {
	req, err := http.NewRequest("GET", testServer.URL+"/proxy", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 500, resp.StatusCode)
}

func TestRouteProxyEmptyURI(t *testing.T) {
	req, err := http.NewRequest("GET", testServer.URL+"/proxy?uri=", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 500, resp.StatusCode)
}
