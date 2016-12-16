package solidproxy

import (
	"crypto/tls"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"
)

const (
	MaxIdleConnections int = 20
	RequestTimeout     int = 5
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
	}

	if agent.Cert != nil {
		proxy.HttpAgentClient = NewAgentClient(agent.Cert, skip)
	}

	return proxy
}

func (p *Proxy) Handler(w http.ResponseWriter, req *http.Request) {
	p.Log.Println("New request from:", req.RemoteAddr, "for URI:", req.URL.String())

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

	p.Log.Println("Proxying request for URI:", req.URL, "and user:", user)

	// build new response
	// no error should exist at this point, it was caught earlier
	// by url.Parse and the server handler
	plain, _ := http.NewRequest(req.Method, req.URL.String(), req.Body)
	// create a new client

	r, err := p.HttpClient.Do(plain)
	if err != nil {
		p.Log.Println("Request execution error:", err)
		w.WriteHeader(500)
		w.Write([]byte(err.Error()))
		return
	}

	// Retry with server credentials if authentication is required
	if r.StatusCode == 401 && len(user) > 0 && p.HttpAgentClient != nil {
		// for debugging
		defer TimeTrack(time.Now(), "Fetching", p.Log)
		// build new response
		authenticated, err := http.NewRequest("GET", req.URL.String(), req.Body)
		authenticated.Header.Set("On-Behalf-Of", user)
		var solutionMsg string
		var client *http.Client
		// Retry the request
		if len(cookies[user]) > 0 { // Use existing cookie
			authenticated.AddCookie(cookies[user][req.Host][0])
			// Create the client
			client = p.HttpClient
			solutionMsg = "Retrying with cookies"
		} else { // Using WebIDTLS client
			client = p.HttpAgentClient
			solutionMsg = "Retrying with WebID-TLS"
		}
		// Close the previous response to reuse the connection
		r.Body.Close()
		r, err = client.Do(authenticated)
		if err != nil {
			p.Log.Println("Request execution error on auth retry:", err)
			w.WriteHeader(500)
			w.Write([]byte(err.Error()))
			return
		}
		// Close the response to reuse the connection
		defer r.Body.Close()

		// Store cookies per user and request host
		if len(r.Cookies()) > 0 {
			cookiesL.Lock()
			// Should store cookies based on domain value AND path from cookie
			cookies[user] = map[string][]*http.Cookie{}
			cookies[user][req.Host] = r.Cookies()
			p.Log.Printf("Cookies: %+v\n", cookies)
			cookiesL.Unlock()
		}
		p.Log.Println("Resource "+authenticated.URL.String(),
			"requires authentication (HTTP 401).", solutionMsg,
			"resulted in HTTP", r.StatusCode)

		p.Log.Println("Got authenticated response code:", r.StatusCode)
		w.Header().Set("Authenticated-Request", "1")
	}

	// Write data back
	// CORS
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Expose-Headers", "User, Triples, Location, Origin, Link, Vary, Last-Modified, Content-Length")
	w.Header().Set("Access-Control-Max-Age", "60")

	// copy headers
	for key, values := range r.Header {
		for _, value := range values {
			w.Header().Set(key, value)
		}
	}

	w.WriteHeader(r.StatusCode)
	// r.Body will be empty at worst, so it should never trigger an error
	body, _ := ioutil.ReadAll(r.Body)
	w.Write(body)

	p.Log.Println("Received public data with status HTTP", r.StatusCode)
	return
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

func NewAgentClient(cert *tls.Certificate, skip bool) *http.Client {
	//TODO handle bad/missing cert
	return &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: MaxIdleConnections,
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{*cert},
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
