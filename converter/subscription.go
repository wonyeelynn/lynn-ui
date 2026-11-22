package converter

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ParseLink parses one subscription link into a Proxy. Inbound nodes and
// external-link nodes are treated identically: both arrive as links, and
// the parser keeps every field for both. There is no code path that drops
// fields for one kind of node.
func ParseLink(link string, opts Options) (*Proxy, error) {
	link = strings.TrimSpace(link)
	if link == "" {
		return nil, fmt.Errorf("empty link")
	}
	// Strip a possible "type://" prefix check before dispatching.
	scheme := link
	if i := strings.Index(link, "://"); i >= 0 {
		scheme = strings.ToLower(link[:i])
	}
	switch scheme {
	case "vless":
		return parseVLESS(link)
	case "hysteria2", "hy2":
		return parseHysteria2(link, opts)
	case "trojan":
		return parseTrojan(link)
	case "vmess":
		return parseVMess(link)
	case "ss":
		return parseShadowsocks(link)
	default:
		return nil, fmt.Errorf("unsupported scheme %q", scheme)
	}
}

// ParseSubscriptionText parses subscription content into proxies. The
// content may be base64-encoded links (the panel's raw subscription) or
// plain links, one per line. Lines that fail to parse are collected as
// warnings and skipped; the rest still convert.
func ParseSubscriptionText(content string, opts Options) ([]*Proxy, []string, error) {
	text := strings.TrimSpace(content)
	if text == "" {
		return nil, nil, fmt.Errorf("empty subscription")
	}

	// If the content is already a Clash YAML document, parse its proxies
	// and re-emit them. This can only preserve the fields that are already
	// there (it cannot restore obfs the panel already dropped), but it does
	// apply the hysteria2 sni / skip-cert-verify defaults.
	if isClashYAML(text) {
		return parseClashYAML(text, opts)
	}

	// Try base64: the panel serves raw links base64-encoded. Only accept
	// the decode if it yields at least one recognisable link.
	if decoded, err := decodeB64(text); err == nil {
		if s := strings.TrimSpace(string(decoded)); looksLikeLinks(s) {
			text = s
		}
	}

	var proxies []*Proxy
	var warnings []string
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := ParseLink(line, opts)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("skip %q: %v", truncate(line, 60), err))
			continue
		}
		proxies = append(proxies, p)
	}
	if err := sc.Err(); err != nil {
		return proxies, warnings, err
	}
	if len(proxies) == 0 {
		return nil, warnings, fmt.Errorf("no usable proxy links found")
	}
	return proxies, warnings, nil
}

func looksLikeLinks(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		for _, p := range []string{"vless://", "hysteria2://", "hy2://", "trojan://", "vmess://", "ss://"} {
			if strings.HasPrefix(strings.ToLower(line), p) {
				return true
			}
		}
		return false
	}
	return false
}

func isClashYAML(text string) bool {
	// A Clash document has a top-level "proxies:" key.
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return line == "proxies:" || strings.HasPrefix(line, "proxies:")
	}
	return false
}

// parseClashYAML reads proxies out of an existing Clash document so they
// can be re-emitted (e.g. to apply the hysteria2 defaults to a panel
// output). Fields already lost by the panel cannot be restored.
func parseClashYAML(text string, opts Options) ([]*Proxy, []string, error) {
	var doc struct {
		Proxies []map[string]interface{} `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return nil, nil, fmt.Errorf("bad Clash YAML: %w", err)
	}
	var proxies []*Proxy
	var warnings []string
	for _, m := range doc.Proxies {
		p := proxyFromClashMap(m, opts)
		if p == nil {
			warnings = append(warnings, "skip unsupported Clash proxy entry")
			continue
		}
		proxies = append(proxies, p)
	}
	if len(proxies) == 0 {
		return nil, warnings, fmt.Errorf("no proxies in Clash YAML")
	}
	return proxies, warnings, nil
}

// proxyFromClashMap converts one Clash proxy map back into the model.
// Only the fields the Clash format carries are recovered.
func proxyFromClashMap(m map[string]interface{}, opts Options) *Proxy {
	str := func(k string) string {
		if v, ok := m[k].(string); ok {
			return v
		}
		return ""
	}
	boolean := func(k string) *bool {
		if v, ok := m[k].(bool); ok {
			return &v
		}
		return nil
	}
	p := &Proxy{
		Name:   str("name"),
		Type:   str("type"),
		Server: str("server"),
		Raw:    "",
		UDP:    true,
	}
	if v, ok := m["port"].(int); ok {
		p.Port = v
	}
	p.UUID = str("uuid")
	p.Password = str("password")
	p.TLS = str("tls") == "true"
	if v, ok := m["tls"].(bool); ok {
		p.TLS = v
	}
	p.ServerName = str("servername")
	if p.ServerName == "" {
		p.ServerName = str("sni")
	}
	p.Fingerprint = str("client-fingerprint")
	p.SkipCertVerify = boolean("skip-cert-verify")
	p.Flow = str("flow")
	p.Encryption = str("encryption")
	p.Network = str("network")
	if alpn, ok := m["alpn"].([]interface{}); ok {
		for _, a := range alpn {
			if s, ok := a.(string); ok {
				p.ALPN = append(p.ALPN, s)
			}
		}
	}
	if ro, ok := m["reality-opts"].(map[string]interface{}); ok {
		r := &RealityOpts{PublicKey: strOf(ro, "public-key"), ShortID: strOf(ro, "short-id")}
		if v, ok := ro["support-x25519mlkem768"].(bool); ok {
			r.SupportX25519MLKEM768 = &v
		}
		p.Reality = r
	}
	if xo, ok := m["xhttp-opts"].(map[string]interface{}); ok {
		p.Path = strOf(xo, "path")
		p.Host = strOf(xo, "host")
		p.Mode = strOf(xo, "mode")
		p.XPaddingBytes = strOf(xo, "x-padding-bytes")
	}
	if wo, ok := m["ws-opts"].(map[string]interface{}); ok {
		p.Path = strOf(wo, "path")
		if h, ok := wo["headers"].(map[string]interface{}); ok {
			p.Host = strOf(h, "Host")
			if p.Host == "" {
				p.Host = strOf(h, "host")
			}
		}
	}
	if go_, ok := m["grpc-opts"].(map[string]interface{}); ok {
		p.ServiceName = strOf(go_, "grpc-service-name")
	}
	p.Obfs = str("obfs")
	p.ObfsPassword = str("obfs-password")
	p.Ports = str("ports")
	p.Up = str("up")
	p.Down = str("down")
	p.Method = str("cipher")
	p.Cipher = str("cipher")
	if v, ok := m["alterId"].(int); ok {
		p.AlterID = v
	}
	if v, ok := m["udp"].(bool); ok {
		p.UDP = v
	}
	// Apply the hysteria2 defaults (the fix) when the entry lacks them.
	if p.Type == "hysteria2" {
		if p.ServerName == "" && opts.HY2SNIHost {
			p.ServerName = p.Server
		}
		if p.SkipCertVerify == nil && opts.HY2SkipVerify {
			b := true
			p.SkipCertVerify = &b
		}
	}
	return p
}

func strOf(m map[string]interface{}, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// FetchSubscription downloads a subscription URL and returns its body.
// A neutral User-Agent is used so panels return the raw base64 links
// instead of a pre-converted Clash document. Transient stalls on the
// egress path are retried (the same jitter the LINE bot sees).
func FetchSubscription(rawURL string) (string, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
		body, err := fetchOnce(rawURL)
		if err == nil {
			return body, nil
		}
		lastErr = err
	}
	return "", lastErr
}

func fetchOnce(rawURL string) (string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "lynn-ui/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("subscription fetch failed: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return "", err
	}
	return string(body), nil
}
