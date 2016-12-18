package solidproxy

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	testMockServer *httptest.Server
)

func init() {
	// ** MOCK Server **
	handler := MockServer()
	// testMockServer = httptest.NewServer(handler)

	// testServer
	testMockServer = httptest.NewUnstartedServer(handler)
	testMockServer.TLS = new(tls.Config)
	testMockServer.TLS.ClientAuth = tls.RequestClientCert
	testMockServer.TLS.NextProtos = []string{"http/1.1"}
	testMockServer.StartTLS()
	testMockServer.URL = strings.Replace(testMockServer.URL, "127.0.0.1", "localhost", 1)
	println(testMockServer.URL)
}

func setOrigin(w http.ResponseWriter, req *http.Request) {
	origin := req.Header.Get("Origin")
	if len(origin) == 0 {
		origin = "*"
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
}

func MockServer() http.Handler {
	// Create new handler
	handler := http.NewServeMux()
	handler.Handle("/401", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		setOrigin(w, req)
		user := req.Header.Get("On-Behalf-Of")
		if len(user) == 0 {
			w.WriteHeader(401)
			w.Write([]byte("Authentication required"))
			return
		}
		if len(req.Cookies()) > 0 {
			cc := req.Cookies()[0]
			if cc.Name != "sample" && cc.Value != "sample" {
				w.WriteHeader(403)
				w.Write([]byte("Bad cookie credentials"))
				return
			}
			w.WriteHeader(200)
			w.Write([]byte("foo"))
			return
		}

		webid, err := WebIDFromReq(req)
		if err != nil {
			w.Write([]byte("\n" + err.Error()))
			return
		}
		if len(webid) > 0 {
			// set cookie
			cookie := &http.Cookie{Name: "sample", Value: "sample", HttpOnly: false}
			http.SetCookie(w, cookie)
			w.WriteHeader(200)
			w.Header().Set("User", webid)
			return
		}

		w.WriteHeader(401)
		w.Write([]byte("Authentication required"))
		return
	}))

	handler.Handle("/200", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		setOrigin(w, req)
		w.Header().Set("User-Agent-Received", req.Header.Get("User-Agent"))
		w.WriteHeader(200)
		w.Write([]byte("foo"))
		return
	}))

	handler.Handle("/method", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		setOrigin(w, req)
		w.WriteHeader(200)
		w.Write([]byte(req.Method))
		return
	}))

	return handler
}

func TestProxyMethodPOST(t *testing.T) {
	req, err := http.NewRequest("POST", testProxyServer.URL+"/proxy?uri="+testMockServer.URL+"/method", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	assert.Equal(t, "POST", string(body))
}

func TestProxyMethodPUT(t *testing.T) {
	req, err := http.NewRequest("PUT", testProxyServer.URL+"/proxy?uri="+testMockServer.URL+"/method", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	assert.Equal(t, "PUT", string(body))
}

func TestProxyMethodPATCH(t *testing.T) {
	req, err := http.NewRequest("PATCH", testProxyServer.URL+"/proxy?uri="+testMockServer.URL+"/method", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	assert.Equal(t, "PATCH", string(body))
}

func TestProxyMethodDELETE(t *testing.T) {
	req, err := http.NewRequest("DELETE", testProxyServer.URL+"/proxy?uri="+testMockServer.URL+"/method", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	assert.Equal(t, "DELETE", string(body))
}

func TestProxyMethodOPTIONS(t *testing.T) {
	req, err := http.NewRequest("OPTIONS", testProxyServer.URL+"/proxy?uri="+testMockServer.URL+"/method", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	assert.Equal(t, "OPTIONS", string(body))
}

func TestProxyHeaders(t *testing.T) {
	origin := "example.org"
	req, err := http.NewRequest("GET", testProxyServer.URL+"/proxy?uri="+testMockServer.URL+"/200", nil)
	assert.NoError(t, err)
	req.Header.Set("Origin", origin)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, GetServerFullName(), resp.Header.Get("User-Agent-Received"))
	assert.Equal(t, origin, resp.Header.Get("Access-Control-Allow-Origin"))
}

func TestProxyNotAuthenticated(t *testing.T) {
	req, err := http.NewRequest("GET", testProxyServer.URL+"/proxy?uri="+testMockServer.URL+"/200", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}

func TestProxyAuthenticated(t *testing.T) {
	alice := "https://alice.com/profile#me"

	req, err := http.NewRequest("GET", testProxyServer.URL+"/proxy?uri="+testMockServer.URL+"/401", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode)

	req, err = http.NewRequest("GET", testProxyServer.URL+"/proxy?uri="+testMockServer.URL+"/401", nil)
	assert.NoError(t, err)
	req.Header.Set("User", alice)
	resp, err = testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	// retry with cookie
	req, err = http.NewRequest("GET", testProxyServer.URL+"/proxy?uri="+testMockServer.URL+"/401", nil)
	assert.NoError(t, err)
	req.Header.Set("User", alice)
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
	assert.Equal(t, 400, resp.StatusCode)
}

func TestProxyNoSkipVerify(t *testing.T) {
	skip := false
	conf := NewServerConfig()
	conf.InsecureSkipVerify = skip
	agent, err := NewAgentLocal(testAgentWebID)
	assert.NoError(t, err)
	proxy := NewProxy(agent, skip)

	handler := NewProxyHandler(conf, proxy)
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
	agent, err := NewAgentLocal(testAgentWebID)
	assert.NoError(t, err)
	proxy := NewProxy(agent, true)

	handler := NewProxyHandler(conf, proxy)
	// testProxyServer
	server := httptest.NewServer(handler)
	server.URL = strings.Replace(server.URL, "127.0.0.1", "localhost", 1)

	req, err := http.NewRequest("GET", server.URL+"/proxy?uri="+testMockServer.URL+"/401", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode)
}

func TestProxyNoAgent(t *testing.T) {
	conf := NewServerConfig()
	agent, err := NewAgent(testAgentWebID)
	assert.NoError(t, err)
	proxy := NewProxy(agent, true)

	assert.Nil(t, proxy.HttpAgentClient)

	handler := NewProxyHandler(conf, proxy)
	// testProxyServer
	server := httptest.NewServer(handler)
	server.URL = strings.Replace(server.URL, "127.0.0.1", "localhost", 1)

	req, err := http.NewRequest("GET", server.URL+"/proxy?uri="+testMockServer.URL+"/401", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode)
}
