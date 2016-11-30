package solidproxy

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
)

var (
	proxy    = goproxy.NewProxyHttpServer()
	cookies  = map[string]map[string][]*http.Cookie{}
	cookiesL = new(sync.RWMutex)
)

func InitProxy(conf *ServerConfig) {
	proxy.OnResponse().DoFunc(func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		// CORS
		r.Header.Set("Access-Control-Allow-Credentials", "true")
		r.Header.Set("Access-Control-Expose-Headers", "User, Triples, Location, Link, Vary, Last-Modified, Content-Length")
		r.Header.Set("Access-Control-Max-Age", "60")

		// Retry with server credentials if authentication is required
		if r.StatusCode == 401 {
			defer TimeTrack(time.Now(), "Fetching")
			var resp *http.Response
			var client *http.Client
			var solutionMsg string
			req, err := http.NewRequest("GET", ctx.Req.URL.String(), ctx.Req.Body)
			req.Header.Add("On-Behalf-Of", conf.User)
			// Retry the request
			if len(cookies[conf.User]) > 0 { // Use existing cookie
				req.AddCookie(cookies[conf.User][ctx.Req.Host][0])
				// Create the client
				client = &http.Client{
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							InsecureSkipVerify: conf.Insecure,
						},
					},
				}
				solutionMsg = "Retrying with cookies"
			} else { // Using WebIDTLS client
				client = webidTlsClient
				solutionMsg = "Retrying with WebID-TLS"
			}
			resp, err = client.Do(req)
			if err != nil {
				Logger.Fatal("GET:", err)
			}
			// Store cookies per user and request host
			if len(resp.Cookies()) > 0 {
				cookiesL.Lock()
				// Should store cookies based on domain value AND path from cookie
				cookies[conf.User] = map[string][]*http.Cookie{}
				cookies[conf.User][ctx.Req.Host] = resp.Cookies()
				Logger.Printf("Cookies: %+v\n", cookies)
				cookiesL.Unlock()
			}
			Logger.Println("Resource "+ctx.Req.URL.String(),
				"requires authentication (HTTP 401).", solutionMsg,
				"resulted in HTTP", resp.StatusCode)
			return resp
		}
		Logger.Println("Received data with status HTTP", r.StatusCode)
		return r
	})
}

func ProxyHandler(w http.ResponseWriter, req *http.Request) {
	toProxy := req.FormValue("uri")
	if len(toProxy) == 0 {
		w.WriteHeader(500)
		w.Write([]byte("No URI was provided to the proxy!"))
		return
	}

	uri, err := url.ParseRequestURI(toProxy)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte("Error parsing URL: " + req.URL.String() + " " + err.Error()))
		Logger.Println("Error parsing URL:", req.URL, err.Error())
		return
	}
	req.URL = uri
	req.Host = uri.Host
	req.RequestURI = uri.RequestURI()
	Logger.Println("Proxying request for:", req.URL)
	proxy.ServeHTTP(w, req)
	return
}

func TimeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	Logger.Printf("%s finished in %s", name, elapsed)
}
