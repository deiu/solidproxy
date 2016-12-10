package solidproxy

import (
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

func ProxyHandler(w http.ResponseWriter, req *http.Request) {
	Logger.Println("New request from:", req.RemoteAddr, "for URI:", req.URL.String())

	uri := req.FormValue("uri")
	if len(uri) == 0 {
		msg := "HTTP 400 - Bad Request. Please provide a URI to the proxy."
		Logger.Println(msg, req.URL.String())
		w.WriteHeader(400)
		w.Write([]byte(msg))
		return
	}

	resource, err := url.ParseRequestURI(uri)
	if err != nil {
		Logger.Println("Error parsing URL:", req.URL, err.Error())
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

	Logger.Println("Proxying request for URI:", req.URL, "and user:", user)

	// build new response
	// no error should exist at this point, it was caught earlier
	// by url.Parse and the server handler
	plain, _ := http.NewRequest(req.Method, req.URL.String(), req.Body)
	// create a new client
	client := NewClient(insecureSkipVerify)
	r, err := client.Do(plain)
	if err != nil {
		Logger.Println("Request execution error:", err)
		w.WriteHeader(500)
		w.Write([]byte(err.Error()))
		return
	}

	// Retry with server credentials if authentication is required
	if r.StatusCode == 401 && len(user) > 0 {
		// for debugging
		defer TimeTrack(time.Now(), "Fetching")
		// build new response
		authenticated, err := http.NewRequest("GET", req.URL.String(), req.Body)
		authenticated.Header.Set("On-Behalf-Of", user)
		var solutionMsg string
		// Retry the request
		if len(cookies[user]) > 0 { // Use existing cookie
			authenticated.AddCookie(cookies[user][req.Host][0])
			// Create the client
			client = NewClient(insecureSkipVerify)
			solutionMsg = "Retrying with cookies"
		} else { // Using WebIDTLS client
			client = NewAgentClient(agentCert)
			solutionMsg = "Retrying with WebID-TLS"
		}
		r, err = client.Do(authenticated)
		if err != nil {
			Logger.Println("Request execution error on auth retry:", err)
			w.WriteHeader(500)
			w.Write([]byte(err.Error()))
			return
		}
		// Store cookies per user and request host
		if len(r.Cookies()) > 0 {
			cookiesL.Lock()
			// Should store cookies based on domain value AND path from cookie
			cookies[user] = map[string][]*http.Cookie{}
			cookies[user][req.Host] = r.Cookies()
			Logger.Printf("Cookies: %+v\n", cookies)
			cookiesL.Unlock()
		}
		Logger.Println("Resource "+authenticated.URL.String(),
			"requires authentication (HTTP 401).", solutionMsg,
			"resulted in HTTP", r.StatusCode)

		Logger.Println("Got authenticated response code:", r.StatusCode)
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

	Logger.Println("Received public data with status HTTP", r.StatusCode)
	return
}

func TimeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	Logger.Printf("%s finished in %s", name, elapsed)
}
