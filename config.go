package solidproxy

const (
	ServerVersion = "v2.1.1"
	ServerName    = "SolidProxy"
)

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

func NewServerConfig() *ServerConfig {
	return &ServerConfig{
		Verbose:            false,
		InsecureSkipVerify: false,
		Port:               "3129",
		EnableTLS:          false,
		Version:            ServerVersion,
	}
}

func GetServerVersion() string {
	return ServerVersion
}

func GetServerName() string {
	return ServerName
}

func GetServerFullName() string {
	return ServerName + "-" + ServerVersion
}
