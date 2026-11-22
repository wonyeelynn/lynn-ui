// Package converter converts proxy subscription links (vless, hysteria2,
// trojan, vmess, shadowsocks) into complete, lossless Clash (Mihomo) YAML.
//
// The problem it fixes: the 3x-ui panel's Clash generator drops fields when
// it converts nodes to Clash YAML -- hysteria2 nodes that arrive as external
// links lose obfs / obfs-password, and ALL hysteria2 nodes lose sni and
// skip-cert-verify. Sublink (the other converter in common use) has the
// mirror bug: it drops the VLESS+REALITY public-key (and
// support-x25519mlkem768 / xhttp-opts). The raw subscription links
// themselves are complete; both converters lose data. lynn-ui parses the
// complete raw links into one unified model and emits every field, treating
// local-inbound nodes and external-link nodes identically (both arrive as
// links; there is no special-casing that drops fields for either kind).
package converter

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Options controls converter behaviour.
type Options struct {
	// HY2SNIHost: when a hysteria2 link carries no sni, use the server
	// hostname as sni. Default true. The server certificate is issued for
	// the hostname, so this keeps verification working without an explicit
	// sni in the link.
	HY2SNIHost bool
	// HY2SkipVerify: when a hysteria2 link carries no insecure flag, emit
	// skip-cert-verify: true. Default true. This matches the output that is
	// known to connect; set to false to let the client verify strictly.
	HY2SkipVerify bool
}

// DefaultOptions returns the recommended defaults.
func DefaultOptions() Options {
	return Options{HY2SNIHost: true, HY2SkipVerify: true}
}

// RealityOpts holds the VLESS+REALITY parameters.
type RealityOpts struct {
	PublicKey               string
	ShortID                 string
	SupportX25519MLKEM768   *bool // nil = not present in the link; omit from output
	SpiderX                 string // spx: parsed and kept, but Mihomo has no such Clash field, so it is not emitted
}

// Proxy is the unified model for one node, regardless of protocol.
// Every field a link can carry is kept here so the Clash builder can emit
// it; nothing is dropped at parse time.
type Proxy struct {
	Name   string
	Type   string // vless, hysteria2, trojan, vmess, ss
	Server string
	Port   int

	UUID     string // vless / vmess
	Password string // hysteria2 / trojan / ss / vmess (rarely)

	// TLS
	TLS            bool
	ServerName     string // sni
	Fingerprint    string // fp
	SkipCertVerify *bool // nil = not present in the link; omit from output
	ALPN           []string

	// REALITY (vless)
	Reality *RealityOpts

	// Flow / encryption
	Flow       string
	Encryption string // vless encryption (e.g. mlkem768...); empty or "none" means none

	// Transport
	Network       string // tcp, ws, grpc, xhttp, ...
	Path          string
	Host          string // ws / xhttp host header
	Mode          string // xhttp mode
	XPaddingBytes string // xhttp
	ServiceName   string // grpc

	// Hysteria2
	Obfs         string
	ObfsPassword string
	Ports        string
	Up           string
	Down         string
	HopInterval  int
	FastOpen     *bool

	// General
	UDP bool

	// VMess
	AlterID int
	Cipher  string // vmess cipher (scy) / ss method is in Method

	// Shadowsocks
	Method     string
	Plugin     string
	PluginOpts string

	Raw string // original link, kept for debugging (never emitted)
}

// parseBool parses "true/false/1/0" (case-insensitive). Returns nil when the
// value is empty or unrecognised, so callers can tell "absent" apart from
// "false".
func parseBool(s string) *bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "yes":
		b := true
		return &b
	case "false", "0", "no":
		b := false
		return &b
	default:
		return nil
	}
}

func parseBoolOr(s string, def bool) bool {
	if b := parseBool(s); b != nil {
		return *b
	}
	return def
}

// splitHostPort splits "host:port" (host may be an IPv6 literal).
func splitHostPort(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("bad server address %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("bad port %q: %w", portStr, err)
	}
	return host, port, nil
}

// decodeName decodes the #fragment of a link into the node name.
func decodeName(frag string) string {
	if frag == "" {
		return ""
	}
	if s, err := url.PathUnescape(frag); err == nil {
		return s
	}
	return frag
}

// queryParams returns the link query as a map of first values.
func queryParams(u *url.URL) map[string]string {
	out := map[string]string{}
	for k, vs := range u.Query() {
		if len(vs) > 0 {
			out[k] = vs[0]
		}
	}
	return out
}

// parseALPN splits a comma-separated alpn value ("h2,http/1.1").
func parseALPN(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
