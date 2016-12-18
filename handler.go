package solidproxy

import (
	"crypto/tls"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"
)

var (
	cookies  = map[string]map[string][]*http.Cookie{}
	cookiesL = new(sync.RWMutex)
)

func InitLogger(verbose bool) *log.Logger {
	logTo := ioutil.Discard
	if verbose {
		logTo = os.Stderr
	}
	return log.New(logTo, "[debug] ", log.Flags()|log.Lshortfile)
}

// NewServer creates a new server handler
func NewProxyHandler(config *ServerConfig, proxy *Proxy) http.Handler {
	logger := InitLogger(config.Verbose)
	logger.Println("\n---- starting proxy server ----")
	logger.Printf("config: %#v\n", config)

	proxy.Log = logger

	// Create new handler
	handler := http.NewServeMux()

	// ****** Routes Middleware ******

	// Proxy handler
	// The proxy handler uses the standard ResponseWriter and Request objects
	handler.HandleFunc("/proxy", proxy.Handler)

	return handler
}

func NewAgentHandler(config *ServerConfig, agent *Agent) http.Handler {
	logger := InitLogger(config.Verbose)
	logger.Println("\n---- starting agent server ----")
	logger.Printf("config: %#v\n", config)
	agent.Log = logger

	// Create new handler
	handler := http.NewServeMux()

	// Agent's WebID handler
	handler.HandleFunc("/webid", agent.Handler)

	return handler
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
