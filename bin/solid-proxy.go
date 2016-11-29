package main

import (
	"net/http"
	"os"

	"github.com/solid/solidproxy"
)

func main() {
	config := solidproxy.NewServerConfig()

	if len(os.Getenv("SOLIDPROXY_VERBOSE")) == 0 {
		config.Verbose = false // default= true
	}
	if len(os.Getenv("SOLIDPROXY_PORT")) > 0 {
		config.Port = os.Getenv("SOLIDPROXY_PORT") // default= :3129
	}
	if len(os.Getenv("SOLIDPROXY_AGENT")) > 0 {
		config.Agent = os.Getenv("SOLIDPROXY_AGENT")
	}
	if len(os.Getenv("SOLIDPROXY_USER")) > 0 {
		config.User = os.Getenv("SOLIDPROXY_USER")
	}

	// Create a new server
	e := solidproxy.NewServer(config)
	// Start server
	println("Starting SolidProxy", solidproxy.GetVersion())

	// set config values
	s := &http.Server{
		Addr:    ":" + config.Port,
		Handler: e,
	}
	// start server
	e.StartServer(s)
}
