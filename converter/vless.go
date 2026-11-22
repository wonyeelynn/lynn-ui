package converter

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// parseVLESS parses a vless:// link.
//
//	vless://uuid@host:port?encryption=none&flow=xtls-rprx-vision&fp=chrome
//	  &pbk=<public-key>&security=reality&sid=<short-id>
//	  &sni=<server-name>&spx=<spider-x>&support-x25519mlkem768=true&type=tcp
//	  #name
//
// All parameters are preserved in the model. The Clash builder emits the
// ones Mihomo understands (public-key, short-id, support-x25519mlkem768,
// flow, fingerprint, servername, network, xhttp-opts, ...). spx is kept in
// the model but not emitted: Mihomo's reality-opts has no such field, and
// the panel's own working VLESS output does not include it either.
func parseVLESS(link string) (*Proxy, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("bad vless link: %w", err)
	}
	if u.User == nil || u.Host == "" {
		return nil, fmt.Errorf("bad vless link %q: missing uuid@host", link)
	}
	uuid := u.User.Username()
	host, port, err := splitHostPort(u.Host)
	if err != nil {
		return nil, err
	}

	q := queryParams(u)
	p := &Proxy{
		Name:   decodeName(u.Fragment),
		Type:   "vless",
		Server: host,
		Port:   port,
		UUID:   uuid,
		Raw:    link,
		UDP:    true, // the panel emits udp: true for vless; keep it
	}

	// TLS / security
	switch strings.ToLower(q["security"]) {
	case "reality":
		p.TLS = true
		p.Reality = &RealityOpts{
			PublicKey: q["pbk"],
			ShortID:   q["sid"],
			SpiderX:   q["spx"],
		}
		if b := parseBool(q["support-x25519mlkem768"]); b != nil {
			p.Reality.SupportX25519MLKEM768 = b
		}
	case "tls":
		p.TLS = true
	case "none", "":
		p.TLS = false
	default:
		// Unknown security value: treat anything non-none as TLS.
		p.TLS = true
	}
	if v := parseBool(q["insecure"]); v != nil {
		p.SkipCertVerify = v
	}
	p.ServerName = q["sni"]
	p.Fingerprint = q["fp"]
	p.ALPN = parseALPN(q["alpn"])

	p.Flow = q["flow"]
	if enc := q["encryption"]; enc != "" && enc != "none" {
		p.Encryption = enc
	}

	// Transport
	typ := strings.ToLower(q["type"])
	switch typ {
	case "", "tcp", "raw":
		p.Network = "tcp"
	case "splithttp":
		p.Network = "xhttp"
	default:
		p.Network = typ
	}
	p.Path = q["path"]
	p.Host = q["host"]
	p.Mode = q["mode"]
	p.ServiceName = q["serviceName"]
	if v := q["x_padding_bytes"]; v != "" {
		p.XPaddingBytes = v
	}
	// The link may also carry an "extra" JSON object
	// {"mode":"auto","xPaddingBytes":"100-1000"}; use it as a fallback
	// when the top-level params are absent.
	if q["extra"] != "" {
		var extra struct {
			Mode          string `json:"mode"`
			XPaddingBytes string `json:"xPaddingBytes"`
		}
		if json.Unmarshal([]byte(q["extra"]), &extra) == nil {
			if p.Mode == "" {
				p.Mode = extra.Mode
			}
			if p.XPaddingBytes == "" {
				p.XPaddingBytes = extra.XPaddingBytes
			}
		}
	}
	if v := parseBool(q["udp"]); v != nil {
		p.UDP = *v
	}
	return p, nil
}
