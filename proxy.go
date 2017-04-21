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
	MaxIdleConnections int = 20
	RequestTimeout     int = 2
)

var (
	cookies  = map[string]map[string][]*http.Cookie{}
	cookiesL = new(sync.RWMutex)

	privateUris  = map[string]bool{}
	privateUrisL = new(sync.RWMutex)
)

type Proxy struct {
	HttpClient      *http.Client
	HttpAgentClient *http.Client
	Log             *log.Logger
	Agent           *Agent
}

func NewProxy(agent *Agent, skip bool) *Proxy {
	proxy := &Proxy{
		HttpClient: NewClient(skip),
		Agent:      agent,
		Log:        InitLogger(false),
	}

	if agent.Cert != nil {
		proxy.HttpAgentClient = agent.NewAgentClient(skip)
	}

	return proxy
}

func (p *Proxy) Handler(w http.ResponseWriter, req *http.Request) {
	p.Log.Println("New request from:", req.RemoteAddr, "for URI:", req.URL.String())
	// Log the time it takes to finish the request (for debugging)
	defer TimeTrack(time.Now(), req.Method+" operation", p.Log)

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
		p.ExecError(w, err)
		return
	}
	// the resource might have turned public, no need to remember it anymore
	if r.StatusCode >= 200 && r.StatusCode <= 400 {
		forgetUri(req.URL.String())
	}
	// Retry with server credentials if authentication is required
	if r.StatusCode == 401 {
		// Close the response to reuse the connection
		defer r.Body.Close()

		saved := rememberUri(req.URL.String())
		if saved {
			p.Log.Println(req.URL.String(), "saved to auth list")
		}
		if len(user) > 0 && p.HttpAgentClient != nil {
			authenticated = true
			r, err = p.NewRequest(req, user, authenticated)
			if err != nil {
				p.ExecError(w, err)
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

func CopyHeaders(from http.Header, to http.Header) {
	for key, values := range from {
		for _, value := range values {
			if key != "User" || key != "Cookie" {
				to.Set(key, value)
			}
		}
	}
}

func (p *Proxy) NewRequest(req *http.Request, user string, authenticated bool) (*http.Response, error) {
	// prepare new request
	request, err := http.NewRequest(req.Method, req.URL.String(), req.Body)
	// copy headers
	CopyHeaders(req.Header, request.Header)
	// overwrite User Agent
	request.Header.Set("User-Agent", GetServerFullName())

	// build new response
	if !authenticated || len(user) == 0 {
		return p.HttpClient.Do(request)
	}

	request.Header.Set("On-Behalf-Of", user)
	solutionMsg := "Retrying with WebID-TLS"

	// Retry the request
	if len(cookies[user]) > 0 && len(cookies[user][req.Host]) > 0 { // Use existing cookie
		solutionMsg = "Retrying with cookies"
		request.AddCookie(cookies[user][req.Host][0])
	}
	// perform the request
	r, err := p.HttpAgentClient.Do(request)
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

func rememberUri(uri string) bool {
	if !privateUris[uri] {
		privateUrisL.Lock()
		privateUris[uri] = true
		privateUrisL.Unlock()
		return true
	}
	return false
}

func forgetUri(uri string) bool {
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

func (p *Proxy) ExecError(w http.ResponseWriter, err error) {
	p.Log.Println("Request execution error:", err)
	w.WriteHeader(500)
	w.Write([]byte(err.Error()))
}

func NewClient(skip bool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: MaxIdleConnections,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skip,
			},
		},
		Timeout: time.Duration(RequestTimeout) * time.Second,
	}
}

func (agent *Agent) NewAgentClient(skip bool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: MaxIdleConnections,
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{*agent.Cert},
				InsecureSkipVerify: skip,
			},
		},
		Timeout: time.Duration(RequestTimeout) * time.Second,
	}
}

func TimeTrack(start time.Time, name string, logger *log.Logger) {
	elapsed := time.Since(start)
	logger.Printf("%s finished in %s", name, elapsed)
}
