package solidproxy

import (
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

var (
	Logger *log.Logger
)

// NewServer creates a new server handler
func NewServer(config *ServerConfig) *echo.Echo {
	Logger = log.New(ioutil.Discard, "", 0)
	if config.Verbose {
		Logger = log.New(os.Stderr, debugPrefix, debugFlags)
	}

	Logger.Println("---- starting server ----")
	Logger.Printf("config: %#v\n", config)

	// Init proxy
	InitProxy(config)
	InitAgentWebID(config)

	// Create new handler
	handler := echo.New()

	// Recover in case of panics
	handler.Use(middleware.Recover())

	// ****** Routes Middleware ******

	// Proxy handler
	// The proxy library uses the standard ResponseWriter and Request objects
	handler.Any("/proxy", echo.WrapHandler(http.HandlerFunc(ProxyHandler)))

	// Agent's WebID handler
	handler.OPTIONS("/webid", WebIDHandler)
	handler.HEAD("/webid", WebIDHandler)
	handler.GET("/webid", WebIDHandler)

	return handler
}
