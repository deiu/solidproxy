package solidproxy

var (
	SERVER_VERSION = "v0.1.0"
)

type ServerConfig struct {
	Verbose            bool
	InsecureSkipVerify bool
	Version            string
	Agent              string
	User               string
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
		Version:            SERVER_VERSION,
	}
}

func GetVersion() string {
	return SERVER_VERSION
}
