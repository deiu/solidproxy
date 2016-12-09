package solidproxy

import (
	"crypto/tls"
	"log"
	"net/http"
	"sync"

	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

var (
	Logger             *log.Logger
	agentWebID         string
	userWebID          string
	insecureSkipVerify bool

	cookies  = map[string]map[string][]*http.Cookie{}
	cookiesL = new(sync.RWMutex)
)

// NewServer creates a new server handler
func NewProxyHandler(config *ServerConfig) *echo.Echo {
	Logger.Println("\n---- starting proxy server ----")
	Logger.Printf("config: %#v\n", config)

	// set local variables used by the proxy client
	agentWebID = config.Agent
	userWebID = config.User
	insecureSkipVerify = config.InsecureSkipVerify

	// Create new handler
	handler := echo.New()

	// Recover in case of panics
	handler.Use(middleware.Recover())

	// ****** Routes Middleware ******

	// Proxy handler
	// The proxy handler uses the standard ResponseWriter and Request objects
	handler.Any("/proxy", echo.WrapHandler(http.HandlerFunc(ProxyHandler)))
	// Catch all other routes with 501 - Not Implemented
	handler.Any("/*", func(c echo.Context) error {
		return c.String(http.StatusNotImplemented, "Not implemented")
	})

	return handler
}

func NewAgentHandler(config *ServerConfig) *echo.Echo {
	Logger.Println("\n---- starting agent server ----")
	Logger.Printf("config: %#v\n", config)

	// Init
	err := InitAgentWebID(config)
	if err != nil {
		panic(err)
	}

	// Create new handler
	handler := echo.New()

	// Recover in case of panics
	handler.Use(middleware.Recover())

	// Agent's WebID handler
	handler.OPTIONS("/webid", echo.WrapHandler(http.HandlerFunc(WebIDHandler)))
	handler.HEAD("/webid", echo.WrapHandler(http.HandlerFunc(WebIDHandler)))
	handler.GET("/webid", echo.WrapHandler(http.HandlerFunc(WebIDHandler)))
	// Catch all other routes with 501 - Not Implemented
	handler.Any("/*", func(c echo.Context) error {
		return c.String(http.StatusNotImplemented, "Not implemented")
	})

	return handler
}

func NewClient(skip bool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skip,
			},
		},
	}
}

func NewTLSConfig(config *ServerConfig) (*tls.Config, error) {
	TLSConfig := new(tls.Config)
	TLSConfig.MinVersion = tls.VersionTLS12
	// enable HTTP/2
	TLSConfig.NextProtos = []string{"h2"}
	// use strong crypto
	TLSConfig.PreferServerCipherSuites = true
	TLSConfig.CurvePreferences = []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256}
	TLSConfig.CipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	}
	TLSConfig.Certificates = make([]tls.Certificate, 1)
	TLSConfig.Certificates[0], err = tls.LoadX509KeyPair(config.TLSCert, config.TLSKey)
	return TLSConfig, err
}
