package option

type CNSOptions struct {
	DialerOptions
	ServerOptions
	EncryptPassword string           `json:"encrypt_password,omitempty"`
	UDPFlag         string           `json:"udp_flag,omitempty"`
	ProxyKey        string           `json:"proxy_key,omitempty"`
	UDPOverTCP      bool             `json:"udp_over_tcp,omitempty"`
	OutboundTLSOptionsContainer
}
