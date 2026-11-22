package converter

import (
	"fmt"
	"net/url"
	"strings"
)

// parseShadowsocks parses an ss:// link. Three shapes are accepted:
//
//	ss://base64(method:password@host:port)#name          (legacy, whole part encoded)
//	ss://base64(method:password)@host:port#name          (method:password encoded only)
//	ss://method:password@host:port#name                  (plain)
func parseShadowsocks(link string) (*Proxy, error) {
	rest := strings.TrimPrefix(link, "ss://")
	name := ""
	if i := strings.LastIndex(rest, "#"); i >= 0 {
		name = decodeName(rest[i+1:])
		rest = rest[:i]
	}

	// Split off the "@host:port" tail if present in plain form.
	var userinfo, hostport string
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		userinfo, hostport = rest[:i], rest[i+1:]
	} else {
		userinfo, hostport = rest, ""
	}

	method, password := "", ""
	if hostport != "" {
		// userinfo may itself be base64(method:password).
		if b, err := decodeB64(userinfo); err == nil && strings.Contains(string(b), ":") {
			userinfo = string(b)
		}
		if i := strings.Index(userinfo, ":"); i >= 0 {
			method, password = userinfo[:i], userinfo[i+1:]
		} else {
			return nil, fmt.Errorf("bad ss link %q: missing method:password", link)
		}
	} else {
		// Whole thing is base64(method:password@host:port).
		b, err := decodeB64(userinfo)
		if err != nil {
			return nil, fmt.Errorf("bad ss link %q: %w", link, err)
		}
		s := string(b)
		if i := strings.LastIndex(s, "@"); i < 0 {
			return nil, fmt.Errorf("bad ss link %q: missing @host", link)
		} else {
			if j := strings.Index(s[:i], ":"); j >= 0 {
				method, password = s[:j], s[j+1:]
			}
			hostport = s[i+1:]
		}
	}

	// hostport may carry a query string (?plugin=...).
	if u, err := url.Parse("//" + hostport); err == nil {
		hostport = u.Host
		_ = u
	}
	host, port, err := splitHostPort(hostport)
	if err != nil {
		return nil, err
	}

	p := &Proxy{
		Name:     name,
		Type:     "ss",
		Server:   host,
		Port:     port,
		Password: password,
		Method:   method,
		Raw:      link,
		UDP:      true,
	}
	// Plugin parameters, if any, live in the query part of the original.
	if u, err := url.Parse(link); err == nil {
		q := queryParams(u)
		p.Plugin = q["plugin"]
		if p.Plugin == "" {
			// Some links put plugin options after ";" in the method field.
			if i := strings.Index(method, ";"); i >= 0 {
				p.Method = method[:i]
				p.PluginOpts = method[i+1:]
			}
		}
	}
	return p, nil
}
