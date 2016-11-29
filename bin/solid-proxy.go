package main

import (
	"net/http"
	"os"

	"github.com/deiu/solidproxy"
)

func main() {
	config := solidproxy.NewServerConfig()

	if len(os.Getenv("SOLIDPROXY_VERBOSE")) == 0 {
		config.Verbose = false // default= true
	}
	if len(os.Getenv("SOLIDPROXY_PORT")) > 0 {
		config.Port = os.Getenv("SOLIDPROXY_PORT") // default= :3129
	}
	if len(os.Getenv("SOLIDPROXY_WEBID")) > 0 {
		config.WebID = os.Getenv("SOLIDPROXY_WEBID")
	}

	// Create a new server
	e := solidproxy.NewServer(config)
	// Start server
	println("Starting Solid-proxy", solidproxy.GetVersion())

	// set config values
	s := &http.Server{
		Addr:    ":" + config.Port,
		Handler: e,
	}
	// start server
	e.StartServer(s)
}
