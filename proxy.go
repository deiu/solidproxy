package solidproxy

import (
	"net/http"
	"net/url"

	"github.com/elazarl/goproxy"
)

var (
	proxy = goproxy.NewProxyHttpServer()
)

func init() {
	proxy.OnResponse().DoFunc(func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if r.StatusCode == 401 {
			Logger.Println(ctx.Req.URL)
			client := &http.Client{}
			req, err := http.NewRequest("GET", ctx.Req.URL.String(), ctx.Req.Body)
			req.Header.Add("On-Behalf-Of", "https://deiu.me/profile#me")
			resp, err := client.Do(req)
			if err != nil {
				Logger.Fatal("GET:", err)
			}
			return resp
		}
		// CORS
		r.Header.Set("Access-Control-Allow-Credentials", "true")
		r.Header.Set("Access-Control-Expose-Headers", "User, Triples, Location, Link, Vary, Last-Modified, Content-Length")
		r.Header.Set("Access-Control-Max-Age", "60")
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
