package solidproxy

import (
	"log"
)

var (
	SERVER_VERSION = "v0.0.1"
	debugFlags     = log.Flags() | log.Lshortfile
	debugPrefix    = "[debug] "
)

type ServerConfig struct {
	Verbose  bool
	Insecure bool
	Port     string
	Version  string
	Agent    string
	User     string
}

func NewServerConfig() *ServerConfig {
	return &ServerConfig{
		Verbose:  false,
		Insecure: false,
		Port:     "3129",
		Version:  SERVER_VERSION,
	}
}

func GetVersion() string {
	return SERVER_VERSION
}
