package main

import (
	"crypto/tls"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/labstack/echo"
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
	solidproxy.Logger = log.New(ioutil.Discard, "", 0)

	if len(os.Getenv("SOLIDPROXY_VERBOSE")) > 0 {
		configProxy.Verbose = true // default= false
		configAgent.Verbose = true // default= false
		solidproxy.Logger = log.New(os.Stderr, debugPrefix, debugFlags)
	}
	if len(os.Getenv("SOLIDPROXY_INSECURE")) > 0 {
		configProxy.InsecureSkipVerify = true // default= false
	}
	if len(os.Getenv("SOLIDPROXY_AGENT")) > 0 {
		configProxy.Agent = os.Getenv("SOLIDPROXY_AGENT")
		configAgent.Agent = os.Getenv("SOLIDPROXY_AGENT")
	}
	if len(os.Getenv("SOLIDPROXY_USER")) > 0 {
		configProxy.User = os.Getenv("SOLIDPROXY_USER")
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
		configProxy.EnableTLS = true // default= true
		configAgent.EnableTLS = true // default= true
	}
	// Agent config
	if len(os.Getenv("SOLIDPROXY_AGENTPORT")) > 0 {
		configAgent.Port = os.Getenv("SOLIDPROXY_AGENTPORT") // default= :3200
	}

	// Create handlers
	proxyHandler := solidproxy.NewProxyServer(configProxy)
	agentHandler := solidproxy.NewAgentServer(configAgent)
	// Start server
	solidproxy.Logger.Println("Starting SolidProxy", solidproxy.GetVersion())

	// start proxy server
	proxyServer, err := NewServer(proxyHandler, configProxy)
	if err != nil {
		solidproxy.Logger.Println("Cannot start proxy server:", err.Error())
		return
	}
	agentServer, err := NewServer(agentHandler, configAgent)
	if err != nil {
		solidproxy.Logger.Println("Cannot start agent server:", err.Error())
		return
	}

	// Start servers
	go agentHandler.StartServer(agentServer)
	proxyHandler.StartServer(proxyServer)
}

func NewServer(handler *echo.Echo, config *solidproxy.ServerConfig) (*http.Server, error) {
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
		s.TLSConfig = new(tls.Config)
		s.TLSConfig.MinVersion = tls.VersionTLS12
		// enable HTTP/2
		s.TLSConfig.NextProtos = []string{"h2"}
		// use strong crypto
		s.TLSConfig.PreferServerCipherSuites = true
		s.TLSConfig.CurvePreferences = []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256}
		s.TLSConfig.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		}
		s.TLSConfig.Certificates = make([]tls.Certificate, 1)
		s.TLSConfig.Certificates[0], err = tls.LoadX509KeyPair(config.TLSCert, config.TLSKey)
		if err != nil {
			return s, err
		}
	}
	return s, nil
}
