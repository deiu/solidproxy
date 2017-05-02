package solidproxy

const (
	// ServerVersion is used to display the server version number during HTTP requests
	ServerVersion = "v2.1.2"
	// ServerName is used to display the server name during HTTP requests
	ServerName = "SolidProxy"
)

// ServerConfig contains all the configuration parameters for the proxy server
type ServerConfig struct {
	Verbose            bool
	InsecureSkipVerify bool
	Version            string
	Agent              string
	EnableTLS          bool
	TLSKey             string
	TLSCert            string
	Port               string
}

// NewServerConfig creates a new ServerConfig object with a few default settings
func NewServerConfig() *ServerConfig {
	return &ServerConfig{
		Verbose:            false,
		InsecureSkipVerify: false,
		Port:               "3129",
		EnableTLS:          false,
		Version:            ServerVersion,
	}
}

// GetServerVersion returns the current server version
func GetServerVersion() string {
	return ServerVersion
}

// GetServerName returns the current server name
func GetServerName() string {
	return ServerName
}

// GetServerFullName returns the concatenated server name and version
func GetServerFullName() string {
	return ServerName + "-" + ServerVersion
}
