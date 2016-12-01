package solidproxy

import (
	"log"
	"net/http"

	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

var (
	Logger *log.Logger
)

// NewServer creates a new server handler
func NewProxyServer(config *ServerConfig) *echo.Echo {
	Logger.Println("---- starting proxy server ----")
	Logger.Printf("config: %#v\n", config)

	// Init proxy
	InitProxy(config)

	// Create new handler
	handler := echo.New()

	// Recover in case of panics
	handler.Use(middleware.Recover())

	// ****** Routes Middleware ******

	// Proxy handler
	// The proxy library uses the standard ResponseWriter and Request objects
	handler.Any("/proxy", echo.WrapHandler(http.HandlerFunc(ProxyHandler)))
	// Catch all other routes with 501 - Not Implemented
	handler.Any("/*", func(c echo.Context) error {
		return c.String(http.StatusNotImplemented, "Not implemented")
	})

	return handler
}

func NewAgentServer(config *ServerConfig) *echo.Echo {
	Logger.Println("---- starting agent server ----")
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
