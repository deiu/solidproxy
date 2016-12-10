package solidproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo"
	"github.com/stretchr/testify/assert"
)

var (
	testMockServer *httptest.Server
)

func init() {
	// ** MOCK Server **
	e := MockServer()

	// testServer
	testMockServer = httptest.NewServer(e)
	testMockServer.URL = strings.Replace(testMockServer.URL, "127.0.0.1", "localhost", 1)
}

func MockServer() *echo.Echo {
	// Create new handler
	handler := echo.New()

	handler.GET("/401", func(c echo.Context) error {
		req := c.Request()
		user := req.Header.Get("On-Behalf-Of")
		if len(user) == 0 {
			return c.String(401, "Authentication required")
		}
		if len(req.Cookies()) > 0 {
			cc := req.Cookies()[0]
			if cc.Name != "sample" && cc.Value != "sample" {
				return c.String(403, "Bad cookie credentials")
			}
			return c.String(200, "foo")
		}

		// set cookie
		cookie := &http.Cookie{Name: "sample", Value: "sample", HttpOnly: false}
		http.SetCookie(c.Response().Writer(), cookie)
		return c.String(200, "foo")
	})

	handler.GET("/200", func(c echo.Context) error {
		return c.String(200, "foo")
	})

	return handler
}

func TestProxyNotAuthenticated(t *testing.T) {
	req, err := http.NewRequest("GET", testProxyServer.URL+"/proxy?uri="+testMockServer.URL+"/200", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}

func TestProxyAuthenticated(t *testing.T) {
	req, err := http.NewRequest("GET", testProxyServer.URL+"/proxy?uri="+testMockServer.URL+"/401", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode)

	req, err = http.NewRequest("GET", testProxyServer.URL+"/proxy?uri="+testMockServer.URL+"/401", nil)
	assert.NoError(t, err)
	req.Header.Set("User", "https://alice.com/profile#me")
	resp, err = testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	req, err = http.NewRequest("GET", testProxyServer.URL+"/proxy?uri="+testMockServer.URL+"/401", nil)
	assert.NoError(t, err)
	req.Header.Set("User", "https://alice.com/profile#me")
	resp, err = testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}

func TestProxyBadURLParse(t *testing.T) {
	req, err := http.NewRequest("GET", testProxyServer.URL+"/proxy?uri=foo", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)

	req, err = http.NewRequest("GET", testProxyServer.URL+"/proxy?uri=http//foo.bar", nil)
	assert.NoError(t, err)
	resp, err = testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

func TestProxyBadRequest(t *testing.T) {
	req, err := http.NewRequest("FOO", testProxyServer.URL+"/proxy?uri=foo", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 405, resp.StatusCode)
}

func TestProxyNoSkipVerify(t *testing.T) {
	conf := NewServerConfig()
	conf.InsecureSkipVerify = false

	handler := NewProxyHandler(conf)
	// testProxyServer
	server := httptest.NewServer(handler)
	server.URL = strings.Replace(server.URL, "127.0.0.1", "localhost", 1)

	req, err := http.NewRequest("GET", server.URL+"/proxy?uri="+testAgentServer.URL+"/webid", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 500, resp.StatusCode)
}

func TestProxyNoUser(t *testing.T) {
	conf := NewServerConfig()

	handler := NewProxyHandler(conf)
	// testProxyServer
	server := httptest.NewServer(handler)
	server.URL = strings.Replace(server.URL, "127.0.0.1", "localhost", 1)

	req, err := http.NewRequest("GET", server.URL+"/proxy?uri="+testMockServer.URL+"/401", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode)
}
