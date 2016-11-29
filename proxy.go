package solidproxy

import (
	"net/http"
	"net/url"

	"github.com/elazarl/goproxy"
)

var (
	proxy = goproxy.NewProxyHttpServer()
)

func InitProxy(conf *ServerConfig) {
	proxy.OnResponse().DoFunc(func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		// CORS
		r.Header.Set("Access-Control-Allow-Credentials", "true")
		r.Header.Set("Access-Control-Expose-Headers", "User, Triples, Location, Link, Vary, Last-Modified, Content-Length")
		r.Header.Set("Access-Control-Max-Age", "60")

		// Retry with server credentials if authentication is required
		if r.StatusCode == 401 {
			Logger.Println("Resource " + ctx.Req.URL.String() + " requires authentication (HTTP 401).")
			req, err := http.NewRequest("GET", ctx.Req.URL.String(), ctx.Req.Body)
			req.Header.Add("On-Behalf-Of", conf.User)
			resp, err := agentClient.Do(req)
			if err != nil {
				Logger.Fatal("GET:", err)
			}
			Logger.Println("Retrying with server credentials...received data with status HTTP", resp.StatusCode)
			return resp
		}
		Logger.Println("Received data with status HTTP", r.StatusCode)
		return r
	})
}

func ProxyHandler(w http.ResponseWriter, req *http.Request) {
	uri, err := url.Parse(req.FormValue("uri"))
	if err != nil {
		Logger.Println("Error parsing URL:", req.URL, err.Error())
	}
	req.URL = uri
	req.Host = uri.Host
	req.RequestURI = uri.RequestURI()
	Logger.Println("Proxying request for:", req.URL)
	proxy.ServeHTTP(w, req)
	return
}
