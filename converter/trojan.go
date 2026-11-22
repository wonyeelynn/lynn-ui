package converter

import (
	"fmt"
	"net/url"
	"strings"
)

// parseTrojan parses a trojan:// link.
//
//	trojan://password@host:port?sni=<name>&fp=chrome&alpn=h2
//	  &type=ws&path=/ws&host=<host>&security=tls#name
func parseTrojan(link string) (*Proxy, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("bad trojan link: %w", err)
	}
	if u.User == nil || u.Host == "" {
		return nil, fmt.Errorf("bad trojan link %q: missing password@host", link)
	}
	password := u.User.Username()
	if pw, ok := u.User.Password(); ok {
		password = pw
	}
	host, port, err := splitHostPort(u.Host)
	if err != nil {
		return nil, err
	}

	q := queryParams(u)
	p := &Proxy{
		Name:     decodeName(u.Fragment),
		Type:     "trojan",
		Server:   host,
		Port:     port,
		Password: password,
		Raw:      link,
		UDP:      true,
		TLS:      true,
	}
	if v := parseBool(q["insecure"]); v != nil {
		p.SkipCertVerify = v
	}
	p.ServerName = q["sni"]
	p.Fingerprint = q["fp"]
	p.ALPN = parseALPN(q["alpn"])

	typ := strings.ToLower(q["type"])
	switch typ {
	case "", "tcp":
		p.Network = "tcp"
	default:
		p.Network = typ
	}
	p.Path = q["path"]
	p.Host = q["host"]
	p.ServiceName = q["serviceName"]
	if v := parseBool(q["udp"]); v != nil {
		p.UDP = *v
	}
	return p, nil
}
