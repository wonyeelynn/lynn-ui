package converter

import (
	"fmt"
	"net/url"
	"strconv"
)

// parseHysteria2 parses a hysteria2:// link.
//
//	hysteria2://password@host:port?alpn=h3&obfs=salamander
//	  &obfs-password=<pw>&security=tls&sni=<name>&insecure=1#name
//
// The password may also arrive as a ?password= query parameter, and the
// userinfo may be "user:password" (the user part is ignored).
//
// This is the protocol the 3x-ui panel gets wrong: its Clash generator
// drops obfs / obfs-password for nodes that arrive as external links and
// never emits sni / skip-cert-verify for any hysteria2 node. lynn-ui keeps
// every field, and -- by default -- fills the two missing ones the way the
// known-working output does: sni falls back to the server hostname and
// skip-cert-verify defaults to true (both controllable via Options).
func parseHysteria2(link string, opts Options) (*Proxy, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("bad hysteria2 link: %w", err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("bad hysteria2 link %q: missing host", link)
	}
	host, port, err := splitHostPort(u.Host)
	if err != nil {
		return nil, err
	}

	// Password: userinfo username (or "user:password" -> password part),
	// falling back to the ?password= query parameter.
	password := ""
	if u.User != nil {
		if pw, ok := u.User.Password(); ok {
			password = pw
		} else {
			password = u.User.Username()
		}
	}

	q := queryParams(u)
	if password == "" {
		password = q["password"]
	}
	// Some clients put the password in ?auth= instead.
	if password == "" {
		password = q["auth"]
	}

	p := &Proxy{
		Name:     decodeName(u.Fragment),
		Type:     "hysteria2",
		Server:   host,
		Port:     port,
		Password: password,
		Raw:      link,
		UDP:      true,
		TLS:      true, // hysteria2 is TLS by protocol design
	}

	// obfs is the field the panel drops for external links; it is kept here.
	p.Obfs = q["obfs"]
	p.ObfsPassword = q["obfs-password"]
	p.ALPN = parseALPN(q["alpn"])
	p.ServerName = q["sni"]
	if v := parseBool(q["insecure"]); v != nil {
		p.SkipCertVerify = v
	} else if v := parseBool(q["skip-cert-verify"]); v != nil {
		p.SkipCertVerify = v
	}
	p.Ports = q["mport"]
	if p.Ports == "" {
		p.Ports = q["ports"]
	}
	p.Up = q["up"]
	if p.Up == "" && q["upmbps"] != "" {
		p.Up = q["upmbps"]
	}
	p.Down = q["down"]
	if p.Down == "" && q["downmbps"] != "" {
		p.Down = q["downmbps"]
	}
	if v := q["hop-interval"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			p.HopInterval = n
		}
	} else if v := q["hop_interval"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			p.HopInterval = n
		}
	}
	if v := parseBool(q["fast-open"]); v != nil {
		p.FastOpen = v
	}
	p.Fingerprint = q["fp"]
	if v := parseBool(q["udp"]); v != nil {
		p.UDP = *v
	}

	// --- The fix: fill the two fields the panel never emits. ---
	// sni: the certificate is issued for the server hostname, so using it
	// keeps verification working when the link carries no sni.
	if p.ServerName == "" && opts.HY2SNIHost {
		p.ServerName = host
	}
	// skip-cert-verify: default true when the link says nothing, matching
	// the output that is known to connect.
	if p.SkipCertVerify == nil && opts.HY2SkipVerify {
		b := true
		p.SkipCertVerify = &b
	}
	return p, nil
}
