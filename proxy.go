// Copyright 2017 Andrei Sambra and the Solid Project team. All rights reserved.
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file.

// Package solidproxy is a transparent browser that can handle WebID-TLS delegated
// auth for resources that require authentication.
//
// A trivial example is:
//
// package main

// import (
// 	"log"
// 	"net/http"
// 	"os"

// 	"github.com/solid/solidproxy"
// )

// func main() {
// 	mux := http.NewServeMux()

// 	// Init logger
// 	logger := log.New(os.Stderr, "[debug] ", log.Flags()|log.Lshortfile)

// 	// Next we create a new (local) agent object with its corresponding key
// 	// pair and profile document and serve it under /agent
// 	// Alternatively, we can create a "remote" agent to which we need to
// 	// provide a cert (tls.Certificate) you can load from somewhere:
// 	// agent, err := solidproxy.NewAgent("https://example.org/agent#me")
// 	// agent.Cert = someTLScert

// 	agent, err := solidproxy.NewAgentLocal("http://localhost:8080/agent#me")
// 	if err != nil {
// 		log.Println("Error creating new agent:", err.Error())
// 		return
// 	}
// 	// assign logger
// 	agent.Log = logger

// 	// Skip verifying trust chain for certificates?
// 	// Use true when dealing with self-signed certs (testing, etc.)
// 	insecureSkipVerify := true
// 	// Create a new proxy object
// 	proxy := solidproxy.NewProxy(agent, insecureSkipVerify)
// 	// assign logger
// 	proxy.Log = logger

// 	// Prepare proxy handler and serve it at http://localhost:8080/proxy
// 	mux.HandleFunc("/proxy", proxy.Handler)

// 	// The handleAgent is only needed if you plan to serve the agent's WebID
// 	// profile yourself; it will be available at http://localhost:8080/agent
// 	mux.HandleFunc("/agent", agent.Handler)

// 	logger.Println("Listening...")
// 	http.ListenAndServe(":8080", mux)
// }

package solidproxy

import (
	"crypto/tls"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	maxIdleConnections int = 20
)

var (
	cookies  = map[string]map[string][]*http.Cookie{}
	cookiesL = new(sync.RWMutex)

	privateUris    = map[string]bool{}
	privateUrisL   = new(sync.RWMutex)
	requestTimeout = 2
)

// Proxy is a structure that encapsulates both clients (agent and fetcher), agent object and logger object.
type Proxy struct {
	HTTPClient      *http.Client
	HTTPAgentClient *http.Client
	Log             *log.Logger
	Agent           *Agent
}

// NewProxy returns a new Proxy object based on the provided agent configuration. The skip parameter is used to indicate if the client should ship server certificate verification.
func NewProxy(agent *Agent, skip bool) *Proxy {
	p := &Proxy{
		HTTPClient: NewClient(skip),
		Agent:      agent,
		Log:        InitLogger(false),
	}

	if agent.Cert != nil {
		p.HTTPAgentClient = agent.NewAgentClient(skip)
	}

	return p
}

// Handler is the main HTTP handler for the proxy/agent server.
func (p *Proxy) Handler(w http.ResponseWriter, req *http.Request) {
	p.Log.Println("New request from:", req.RemoteAddr, "for URI:", req.URL.String())
	// Log the time it takes to finish the request (for debugging)
	defer timeTrack(time.Now(), req.Method+" operation", p.Log)

	uri := req.FormValue("uri")
	if len(uri) == 0 {
		msg := "HTTP 400 - Bad Request. Please provide a URI to the proxy."
		p.Log.Println(msg, req.URL.String())
		w.WriteHeader(400)
		w.Write([]byte(msg))
		return
	}

	resource, err := url.ParseRequestURI(uri)
	if err != nil {
		p.Log.Println("Error parsing URL:", req.URL, err.Error())
		w.WriteHeader(400)
		w.Write([]byte("HTTP 400 - Bad Request. You must provide a valid URI: " + req.URL.String()))
		return
	}
	// rewrite URL
	req.URL = resource
	req.Host = resource.Host
	req.RequestURI = resource.RequestURI()
	// get user
	user := req.Header.Get("User")

	// check if we need to authenticate from the start
	authenticated := false
	if requiresAuth(req.URL.String()) {
		authenticated = true
		p.Log.Println("Request will use credentials for cached URI:", req.URL.String())
	}

	p.Log.Println("Proxying request for URI:", req.URL, "and user:", user, "using Agent:", p.Agent.WebID)

	// build new response
	var r *http.Response
	r, err = p.NewRequest(req, user, authenticated)
	if err != nil {
		p.execError(w, err)
		return
	}
	// the resource might have turned public, no need to remember it anymore
	if r.StatusCode >= 200 && r.StatusCode <= 400 {
		forgetURI(req.URL.String())
	}
	// Retry with server credentials if authentication is required
	if r.StatusCode == 401 {
		// Close the response to reuse the connection
		defer r.Body.Close()

		saved := rememberURI(req.URL.String())
		if saved {
			p.Log.Println(req.URL.String(), "saved to auth list")
		}
		if len(user) > 0 && p.HTTPAgentClient != nil {
			authenticated = true
			r, err = p.NewRequest(req, user, authenticated)
			if err != nil {
				p.execError(w, err)
				return
			}
			defer r.Body.Close()
		}
	}

	// Write data back
	// CORS
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Expose-Headers", "User, Triples, Location, Origin, Link, Vary, Last-Modified, Content-Length")
	w.Header().Set("Access-Control-Max-Age", "60")
	origin := req.Header.Get("Origin")
	if len(origin) > 0 {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}

	// copy headers
	CopyHeaders(r.Header, w.Header())

	w.WriteHeader(r.StatusCode)
	// r.Body will be empty at worst, so it should never trigger an error
	body, _ := ioutil.ReadAll(r.Body)
	w.Write(body)

	p.Log.Println("Response received with HTTP status", r.StatusCode)
	return
}

// CopyHeaders is used to copy headers between two http.Header objects (usually two request/response objects)
func CopyHeaders(from http.Header, to http.Header) {
	for key, values := range from {
		if key != "User" && key != "Cookie" {
			for _, value := range values {
				to.Set(key, value)
			}
		}
	}
}

// NewRequest creates a new HTTP request for a given resource and user.
func (p *Proxy) NewRequest(req *http.Request, user string, authenticated bool) (*http.Response, error) {
	// prepare new request
	request, err := http.NewRequest(req.Method, req.URL.String(), req.Body)
	// copy headers
	CopyHeaders(req.Header, request.Header)
	// overwrite User Agent
	request.Header.Set("User-Agent", GetServerFullName())

	// build new response
	if !authenticated || len(user) == 0 {
		return p.HTTPClient.Do(request)
	}

	request.Header.Set("On-Behalf-Of", user)
	solutionMsg := "Retrying with WebID-TLS"

	// Retry the request
	if len(cookies[user]) > 0 && len(cookies[user][req.Host]) > 0 { // Use existing cookie
		solutionMsg = "Retrying with cookies"
		request.AddCookie(cookies[user][req.Host][0])
	}
	// perform the request
	r, err := p.HTTPAgentClient.Do(request)
	if err != nil {
		return r, err
	}

	// Store cookies per user and request host
	if len(r.Cookies()) > 0 {
		cookiesL.Lock()
		// TODO: should store cookies based on domain value AND path from cookie
		cookies[user] = map[string][]*http.Cookie{}
		cookies[user][req.Host] = r.Cookies()
		p.Log.Printf("Cookies: %+v\n", cookies)
		cookiesL.Unlock()
	}
	p.Log.Println("Resource "+request.URL.String(),
		"requires authentication (HTTP 401).", solutionMsg,
		"resulted in HTTP", r.StatusCode)

	p.Log.Println("Got authenticated response code:", r.StatusCode)
	return r, err
}

func rememberURI(uri string) bool {
	if !privateUris[uri] {
		privateUrisL.Lock()
		privateUris[uri] = true
		privateUrisL.Unlock()
		return true
	}
	return false
}

func forgetURI(uri string) bool {
	if privateUris[uri] {
		delete(privateUris, uri)
		return true
	}
	return false
}

func requiresAuth(uri string) bool {
	if len(privateUris) > 0 && privateUris[uri] {
		return true
	}
	return false
}

func (p *Proxy) execError(w http.ResponseWriter, err error) {
	p.Log.Println("Request execution error:", err)
	w.WriteHeader(500)
	w.Write([]byte(err.Error()))
}

// NewClient creates a new http.Client object to be used for fetching resources. The skip parameter is used to indicate if the client should ship server certificate verification.
func NewClient(skip bool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: maxIdleConnections,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skip,
			},
		},
		Timeout: time.Duration(requestTimeout) * time.Second,
	}
}

// NewAgentClient creates a new http.Client to be used for agent requests. The skip parameter is used to indicate if the client should ship server certificate verification.
func (agent *Agent) NewAgentClient(skip bool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: maxIdleConnections,
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{*agent.Cert},
				InsecureSkipVerify: skip,
			},
		},
		Timeout: time.Duration(requestTimeout) * time.Second,
	}
}

func timeTrack(start time.Time, name string, logger *log.Logger) {
	elapsed := time.Since(start)
	logger.Printf("%s finished in %s", name, elapsed)
}

// SetRequestTimeout sets the timeout value in seconds for all request
func SetRequestTimeout(sec int) {
	requestTimeout = sec
}
