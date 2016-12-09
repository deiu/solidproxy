package solidproxy

import (
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

func ProxyHandler(w http.ResponseWriter, req *http.Request) {
	Logger.Println("New request from:", req.RemoteAddr, "for URI:", req.URL.String())

	user := req.Header.Get("User")
	// override if we have specified a user in config
	if len(userWebID) > 0 {
		user = userWebID
	}

	uri := req.FormValue("uri")
	if len(uri) == 0 {
		msg := "No URI was provided to the proxy!"
		Logger.Println(msg, req.URL.String())
		w.WriteHeader(500)
		w.Write([]byte(msg))
		return
	}

	resource, err := url.ParseRequestURI(uri)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte("Error parsing URL: " + req.URL.String() + " " + err.Error()))
		Logger.Println("Error parsing URL:", req.URL, err.Error())
		return
	}
	req.URL = resource
	req.Host = resource.Host
	req.RequestURI = resource.RequestURI()
	Logger.Println("Proxying request for URI:", req.URL, "and user:", user)

	// build new response
	plain, err := http.NewRequest("GET", req.URL.String(), req.Body)
	if err != nil {
		Logger.Fatal("GET error:", err)
	}
	client := NewClient(insecureSkipVerify)
	r, err := client.Do(plain)
	if err != nil {
		Logger.Fatal("GET error:", err)
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
			Logger.Fatal("GET error:", err)
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
	w.Header().Set("Access-Control-Expose-Headers", "User, Triples, Location, Link, Vary, Last-Modified, Content-Length")
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
