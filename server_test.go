package solidproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
)

var (
	testServer *httptest.Server
	testClient *http.Client
)

func init() {
	conf := NewServerConfig()
	e := NewServer(conf)

	// testServer
	testServer = httptest.NewServer(e)
	testServer.URL = strings.Replace(testServer.URL, "127.0.0.1", "localhost", 1)
	// testClient
	testClient = &http.Client{}
}
