package option

type CNSOutboundOptions struct {
	DialerOptions
	ServerOptions
	Password string      `json:"password,omitempty"`
	Network  NetworkList `json:"network,omitempty"`
	OutboundTLSOptionsContainer
	ProxyKey  string `json:"proxy_key,omitempty"`
	UDPFlag   string `json:"udp_flag,omitempty"`
	UDPTCPBuf int    `json:"udp_tcp_buffer,omitempty"`
}
