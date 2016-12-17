package main

import (
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/solid/solidproxy"
)

var (
	debugPrefix = "[debug] "
	debugFlags  = log.Flags() | log.Lshortfile
)

func main() {
	configProxy := solidproxy.NewServerConfig()
	configAgent := solidproxy.NewServerConfig()
	configAgent.Port = "3200" // set default for agent

	// logger
	logger := log.New(ioutil.Discard, "", 0)

	// Try to recover in case of panics
	defer func() {
		if rec := recover(); rec != nil {
			logger.Println(rec)
			return
		}
	}()

	// Read config from environment
	if len(os.Getenv("SOLIDPROXY_VERBOSE")) > 0 {
		configProxy.Verbose = true // default= false
		configAgent.Verbose = true // default= false
		logger = log.New(os.Stderr, debugPrefix, debugFlags)
	}
	if len(os.Getenv("SOLIDPROXY_INSECURE")) > 0 {
		configProxy.InsecureSkipVerify = true // default= false
		configAgent.InsecureSkipVerify = true // default= false
	}
	if len(os.Getenv("SOLIDPROXY_AGENT")) > 0 {
		configProxy.Agent = os.Getenv("SOLIDPROXY_AGENT")
		configAgent.Agent = os.Getenv("SOLIDPROXY_AGENT")
	}
	if len(os.Getenv("SOLIDPROXY_TLSKEY")) > 0 {
		configProxy.TLSKey = os.Getenv("SOLIDPROXY_TLSKEY")
		configAgent.TLSKey = os.Getenv("SOLIDPROXY_TLSKEY")
	}
	if len(os.Getenv("SOLIDPROXY_TLSCERT")) > 0 {
		configProxy.TLSCert = os.Getenv("SOLIDPROXY_TLSCERT")
		configAgent.TLSCert = os.Getenv("SOLIDPROXY_TLSCERT")
	}
	// Proxy config
	if len(os.Getenv("SOLIDPROXY_PROXYPORT")) > 0 {
		configProxy.Port = os.Getenv("SOLIDPROXY_PROXYPORT") // default= :3129
	}
	// Enable or not HTTPS
	if len(os.Getenv("SOLIDPROXY_ENABLETLS")) > 0 {
		configProxy.EnableTLS = true // default= false
		configAgent.EnableTLS = true // default= false
	}
	// Agent config
	if len(os.Getenv("SOLIDPROXY_AGENTPORT")) > 0 {
		configAgent.Port = os.Getenv("SOLIDPROXY_AGENTPORT") // default= :3200
	}

	// Create new agent
	agent, err := solidproxy.NewAgentLocal(configAgent.Agent)
	if err != nil {
		println("Cannot create new agent:", err.Error())
		return
	}
	agent.Log = logger
	proxy := solidproxy.NewProxy(agent, configAgent.InsecureSkipVerify)
	proxy.Log = logger

	// Create handlers
	agentHandler := solidproxy.NewAgentHandler(configAgent, agent)
	proxyHandler := solidproxy.NewProxyHandler(configProxy, proxy)

	// Create servers
	agentServer, err := NewServer(agentHandler, configAgent)
	if err != nil {
		println("Cannot start agent server:", err.Error())
		return
	}
	proxyServer, err := NewServer(proxyHandler, configProxy)
	if err != nil {
		println("Cannot start proxy server:", err.Error())
		return
	}

	// Start servers
	println("\nStarting SolidProxy", solidproxy.GetVersion())
	go agentServer.ListenAndServe()
	proxyServer.ListenAndServe()
}

func NewServer(handler http.Handler, config *solidproxy.ServerConfig) (*http.Server, error) {
	// Create proxy server listener and set config values
	var err error
	s := &http.Server{
		Addr:    ":" + config.Port,
		Handler: handler,
	}
	if config.EnableTLS {
		if len(config.TLSKey) == 0 || len(config.TLSCert) == 0 {
			return s, errors.New("TLS cert or key missing")
		}
		s.TLSConfig, err = solidproxy.NewTLSConfig(config)
		if err != nil {
			return s, err
		}
	}
	return s, nil
}
