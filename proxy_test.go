package solidproxy

import (
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	testMockServer *httptest.Server
	testURI        = "https://example.org"
)

func init() {
	// ** MOCK Server **
	handler := MockServer()
	// testMockServer = httptest.NewServer(handler)

	// set timeout
	SetRequestTimeout(3)

	// testServer
	testMockServer = httptest.NewUnstartedServer(handler)
	testMockServer.TLS = new(tls.Config)
	testMockServer.TLS.ClientAuth = tls.RequestClientCert
	testMockServer.TLS.NextProtos = []string{"http/1.1"}
	testMockServer.StartTLS()
	testMockServer.URL = strings.Replace(testMockServer.URL, "127.0.0.1", "localhost", 1)
}

func setOrigin(w http.ResponseWriter, req *http.Request) {
	origin := req.Header.Get("Origin")
	if len(origin) == 0 {
		origin = "*"
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
}

func MockServer() http.Handler {
	nonce := "abc123"

	// Create new handler
	handler := http.NewServeMux()

	handler.Handle("/webid-tls", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		setOrigin(w, req)
		user := req.Header.Get("On-Behalf-Of")
		if len(user) == 0 {
			w.WriteHeader(401)
			w.Write([]byte("No User header found"))
			return
		}

		webid, err := WebIDFromReq(req)
		if err != nil {
			w.WriteHeader(400)
			w.Write([]byte("\n" + err.Error()))
			return
		}
		if len(webid) > 0 {
			// set cookie
			cookie := &http.Cookie{Name: "sample-name", Value: "sample-value", HttpOnly: false}
			http.SetCookie(w, cookie)
			w.WriteHeader(200)
			w.Header().Set("User", webid)
			w.Write([]byte("foo"))
			return
		}

		w.WriteHeader(401)
		w.Write([]byte("Authentication required"))
		return
	}))

	handler.Handle("/cookies", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		setOrigin(w, req)
		user := req.Header.Get("On-Behalf-Of")
		if len(user) == 0 {
			w.WriteHeader(401)
			w.Write([]byte("No User header found"))
			return
		}

		if len(req.Cookies()) > 0 {
			cc := req.Cookies()[0]
			if cc.Name != "sample-name" && cc.Value != "sample-value" {
				w.WriteHeader(401)
				w.Write([]byte("Bad cookie credentials"))
				return
			}
			w.WriteHeader(200)
			w.Write([]byte("foo"))
			return
		}

		w.Header().Set("User-Agent-Received", req.Header.Get("User-Agent"))
		w.WriteHeader(401)
		w.Write([]byte("Authentication required"))
		return
	}))

	handler.Handle("/webid-rsa", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		setOrigin(w, req)
		user := req.Header.Get("On-Behalf-Of")
		if len(req.Header.Get("Authorization")) == 0 {
			wwwAuth := `WebID-RSA source="` + req.Host + `", nonce="` + nonce + `"`
			w.Header().Set("WWW-Authenticate", wwwAuth)

			w.WriteHeader(401)
			w.Write([]byte("Authentication required"))
			return
		}
		// check authz
		authH, err := parseRSAAuthorizationHeader(req.Header.Get("Authorization"))
		if err != nil {
			w.WriteHeader(401)
			w.Write([]byte("Bad WebID-RSA authorization credentials"))
			return
		}

		claim := sha1.Sum([]byte(authH.Source + authH.Username + authH.Nonce))
		signature, err := base64.StdEncoding.DecodeString(authH.Signature)

		parser, err := ParseRSAPublicPEMKey(testPubKey)
		if err == nil {
			err = parser.Verify(claim[:], signature)
			if err != nil {
				w.WriteHeader(401)
				w.Write([]byte("Can't verify WebID-RSA signature. " + err.Error()))
				return
			}
		}

		// set cookie
		cookie := &http.Cookie{Name: "bad-name", Value: "bad-value", HttpOnly: false}
		http.SetCookie(w, cookie)
		w.WriteHeader(200)
		w.Header().Set("User-Agent-Received", req.Header.Get("User-Agent"))
		w.Header().Set("User", user)
		w.Write([]byte("foo"))
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

	handler.Handle("/patch", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		setOrigin(w, req)
		// copy body for reuse in subsequent requests
		buf, _ := ioutil.ReadAll(req.Body)
		if req.Header.Get("Content-Length") == "0" || len(buf) == 0 {
			w.WriteHeader(400)
			w.Write([]byte("Empty patch body. Length:" + req.Header.Get("Content-Length")))
			w.Write(buf)
			return
		}

		w.WriteHeader(200)
		w.Write(buf)
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
	assert.NoError(t, err)
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
	assert.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, "PUT", string(body))
}

func TestProxyMethodPATCH(t *testing.T) {
	sparqlData := `INSERT DATA { <http://a.com> <http://b.com> <http://c.com> . }`
	req, err := http.NewRequest("PATCH", testProxyServer.URL+"/proxy?uri="+testMockServer.URL+"/patch", strings.NewReader(sparqlData))
	assert.NoError(t, err)
	req.Header.Add("Content-Type", "application/sparql-update")
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	body, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, sparqlData, string(body))

	req, err = http.NewRequest("PATCH", testProxyServer.URL+"/proxy?uri="+testMockServer.URL+"/patch", strings.NewReader(""))
	assert.NoError(t, err)
	req.Header.Add("Content-Type", "application/sparql-update")
	resp, err = testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
	_, err = ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	resp.Body.Close()
}

func TestProxyMethodDELETE(t *testing.T) {
	req, err := http.NewRequest("DELETE", testProxyServer.URL+"/proxy?uri="+testMockServer.URL+"/method", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	body, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
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
	assert.NoError(t, err)
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

func TestProxyAuthenticated(t *testing.T) {
	alice := "https://alice.com/profile#me"

	req, err := http.NewRequest("GET", testProxyServer.URL+"/proxy?uri="+testMockServer.URL+"/webid-tls", nil)
	assert.NoError(t, err)
	req.Header.Set("User", alice)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	body, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, "foo", string(body))
	assert.Equal(t, 200, resp.StatusCode)

	// retry with cookie
	req, err = http.NewRequest("GET", testProxyServer.URL+"/proxy?uri="+testMockServer.URL+"/cookies", nil)
	assert.NoError(t, err)
	req.Header.Set("User", alice)
	resp, err = testClient.Do(req)
	assert.NoError(t, err)
	body, err = ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, "foo", string(body))
	assert.Equal(t, 200, resp.StatusCode)

	// testServer
	handler := MockServer()
	testMockServer = httptest.NewUnstartedServer(handler)
	testMockServer.TLS = new(tls.Config)
	testMockServer.TLS.ClientAuth = tls.RequestClientCert
	testMockServer.TLS.NextProtos = []string{"http/1.1"}
	testMockServer.StartTLS()
	testMockServer.URL = strings.Replace(testMockServer.URL, "127.0.0.1", "localhost", 1)

	req, err = http.NewRequest("GET", testProxyServer.URL+"/proxy?uri="+testMockServer.URL+"/webid-rsa", nil)
	assert.NoError(t, err)
	resp, err = testClient.Do(req)
	assert.NoError(t, err)
	body, err = ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, 401, resp.StatusCode)

	req, err = http.NewRequest("GET", testProxyServer.URL+"/proxy?uri="+testMockServer.URL+"/webid-rsa", nil)
	assert.NoError(t, err)
	req.Header.Set("User", alice)
	resp, err = testClient.Do(req)
	assert.NoError(t, err)
	body, err = ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, "foo", string(body))
	assert.Equal(t, 200, resp.StatusCode)

	// retry with cookie
	req, err = http.NewRequest("GET", testProxyServer.URL+"/proxy?uri="+testMockServer.URL+"/cookies", nil)
	assert.NoError(t, err)
	req.Header.Set("User", alice)
	resp, err = testClient.Do(req)
	assert.NoError(t, err)
	body, err = ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, 401, resp.StatusCode)
}

func TestProxyNotAuthenticated(t *testing.T) {
	req, err := http.NewRequest("GET", testProxyServer.URL+"/proxy?uri="+testMockServer.URL+"/200", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	req, err = http.NewRequest("GET", testProxyServer.URL+"/proxy?uri="+testMockServer.URL+"/webid-tls", nil)
	assert.NoError(t, err)
	resp, err = testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode)

	req, err = http.NewRequest("GET", testProxyServer.URL+"/proxy?uri="+testMockServer.URL+"/webid-rsa", nil)
	assert.NoError(t, err)
	resp, err = testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode)

	req, err = http.NewRequest("GET", testProxyServer.URL+"/proxy?uri="+testMockServer.URL+"/cookies", nil)
	assert.NoError(t, err)
	resp, err = testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode)
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

	req, err := http.NewRequest("GET", server.URL+"/proxy?uri="+testMockServer.URL+"/webid-tls", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode)

	req, err = http.NewRequest("GET", server.URL+"/proxy?uri="+testMockServer.URL+"/webid-rsa", nil)
	assert.NoError(t, err)
	resp, err = testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode)

	req, err = http.NewRequest("GET", server.URL+"/proxy?uri="+testMockServer.URL+"/cookies", nil)
	assert.NoError(t, err)
	resp, err = testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode)
}

func TestProxyNoAgent(t *testing.T) {
	conf := NewServerConfig()
	agent, err := NewAgent(testAgentWebID)
	assert.NoError(t, err)
	proxy := NewProxy(agent, true)

	assert.Nil(t, proxy.HTTPAgentClient)

	handler := NewProxyHandler(conf, proxy)
	// testProxyServer
	server := httptest.NewServer(handler)
	server.URL = strings.Replace(server.URL, "127.0.0.1", "localhost", 1)

	req, err := http.NewRequest("GET", server.URL+"/proxy?uri="+testMockServer.URL+"/webid-tls", nil)
	assert.NoError(t, err)
	resp, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode)

	req, err = http.NewRequest("GET", server.URL+"/proxy?uri="+testMockServer.URL+"/webid-rsa", nil)
	assert.NoError(t, err)
	resp, err = testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode)

	req, err = http.NewRequest("GET", server.URL+"/proxy?uri="+testMockServer.URL+"/cookies", nil)
	assert.NoError(t, err)
	resp, err = testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode)
}

func TestCopyHeaders(t *testing.T) {
	h1 := &http.Header{}
	h1.Add("User", testAgentWebID)
	h1.Add("Cookie", "abc")
	h1.Add("Content-Type", "text/turtle")

	h2 := &http.Header{}
	CopyHeaders(*h1, *h2)

	assert.Empty(t, h2.Get("User"))
	assert.Empty(t, h2.Get("Cookie"))
	assert.Equal(t, "text/turtle", h2.Get("Content-Type"))
}

func TestMultiCookie(t *testing.T) {
	req, err := http.NewRequest("GET", "example.org", nil)
	assert.NoError(t, err)
	c1 := &http.Cookie{Name: "sample", Value: "test", HttpOnly: false}
	req.AddCookie(c1)
	c2 := &http.Cookie{Name: "Session", Value: "sample", HttpOnly: false}
	req.AddCookie(c2)
	assert.Equal(t, 2, len(req.Cookies()))
}

func TestDeleteCookie(t *testing.T) {
	user := "https://alice.com/profile#me"
	testCookies := map[string]map[string][]*http.Cookie{}
	testCookiesL := new(sync.RWMutex)

	req, err := http.NewRequest("GET", "example.org", nil)
	assert.NoError(t, err)
	c1 := &http.Cookie{Name: "sample", Value: "test", HttpOnly: false}

	testCookies[user] = map[string][]*http.Cookie{}
	testCookies[user]["example.org"] = []*http.Cookie{c1}

	req.Host = "example.com"
	err = forgetCookie(req, user, testCookiesL, testCookies)
	assert.Error(t, err)
}

func TestRememberURI(t *testing.T) {
	assert.True(t, rememberURI(testURI))
}

func TestRequiresAuth(t *testing.T) {
	assert.True(t, requiresAuth(testURI))
}

func TestForgetURI(t *testing.T) {
	assert.True(t, forgetURI(testURI))
	assert.False(t, requiresAuth(testURI))
}
