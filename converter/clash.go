package converter

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// ConvertLinks parses subscription text (base64 or plain links) and returns
// complete Clash (Mihomo) YAML. Every field present in the links is emitted;
// nothing is dropped. When opts.Rules is set, the rules document is merged
// in (proxy-groups, rule-providers, rules, dns); otherwise the output is
// proxies plus the minimal PROXY group only.
func ConvertLinks(input string, opts Options) ([]byte, error) {
	proxies, warnings, err := ParseSubscriptionText(input, opts)
	if err != nil {
		return nil, err
	}
	for _, w := range warnings {
		// Warnings are reported on stderr by the caller; conversion continues.
		_ = w
	}
	if opts.Rules != nil {
		return BuildClashWithRules(proxies, opts.Rules)
	}
	return BuildClash(proxies)
}

// ConvertSubscription fetches a subscription URL and converts it to Clash YAML.
func ConvertSubscription(rawURL string, opts Options) ([]byte, error) {
	body, err := FetchSubscription(rawURL)
	if err != nil {
		return nil, err
	}
	return ConvertLinks(body, opts)
}

// BuildClash renders proxies as a Clash (Mihomo) YAML document: a "proxies"
// list plus a minimal "PROXY" select group so the document is directly
// usable as a subscription.
func BuildClash(proxies []*Proxy) ([]byte, error) {
	list, err := buildProxyList(proxies)
	if err != nil {
		return nil, err
	}
	doc := map[string]any{
		"proxies": list,
		"proxy-groups": []map[string]any{
			proxyGroup(),
		},
	}
	return encodeClash(doc)
}

// BuildClashWithRules renders proxies plus a rules document: the minimal
// PROXY group first, then the rules file's proxy-groups, rule-providers,
// rules and dns. The rules document is validated by ParseRules before it
// gets here, so a group named PROXY or a dangling rule target cannot
// reach the output.
func BuildClashWithRules(proxies []*Proxy, rules *Rules) ([]byte, error) {
	list, err := buildProxyList(proxies)
	if err != nil {
		return nil, err
	}
	groups := []map[string]any{proxyGroup()}
	groups = append(groups, rules.ProxyGroups...)
	doc := map[string]any{
		"proxies":      list,
		"proxy-groups": groups,
		"rules":        rules.Rules,
	}
	if len(rules.RuleProviders) > 0 {
		doc["rule-providers"] = rules.RuleProviders
	}
	if rules.DNS != nil {
		doc["dns"] = rules.DNS
	}
	return encodeClash(doc)
}

// proxyGroup is lynn-ui's minimal PROXY select group. Every rule group in
// the merged document references PROXY, so it must always be present and
// first.
func proxyGroup() map[string]any {
	return map[string]any{
		"name":                "PROXY",
		"type":                "select",
		"proxies":             []string{"DIRECT"},
		"include-all-proxies": true,
	}
}

func buildProxyList(proxies []*Proxy) ([]map[string]any, error) {
	list := make([]map[string]any, 0, len(proxies))
	for _, p := range proxies {
		m, err := proxyToClash(p)
		if err != nil {
			return nil, err
		}
		list = append(list, m)
	}
	return list, nil
}

func encodeClash(doc map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("yaml encode: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// proxyToClash maps one Proxy to a Clash proxy entry. Keys are emitted only
// when set, so the output carries exactly what the link carried -- plus the
// hysteria2 defaults applied at parse time. yaml.v3 sorts map keys, which
// matches the panel's alphabetical output.
func proxyToClash(p *Proxy) (map[string]any, error) {
	m := map[string]any{
		"name":   p.Name,
		"type":   p.Type,
		"server": p.Server,
		"port":   p.Port,
	}
	if p.UDP {
		m["udp"] = true
	}
	setStr := func(k, v string) {
		if v != "" {
			m[k] = v
		}
	}
	setBool := func(k string, v *bool) {
		if v != nil {
			m[k] = *v
		}
	}

	switch p.Type {
	case "vless":
		setStr("uuid", p.UUID)
		if p.TLS {
			m["tls"] = true
		}
		setStr("servername", p.ServerName)
		setStr("client-fingerprint", p.Fingerprint)
		setStr("network", p.Network)
		setStr("flow", p.Flow)
		setStr("encryption", p.Encryption)
		if len(p.ALPN) > 0 {
			m["alpn"] = p.ALPN
		}
		setBool("skip-cert-verify", p.SkipCertVerify)
		if p.Reality != nil {
			ro := map[string]any{}
			setStrInto(ro, "public-key", p.Reality.PublicKey)
			setStrInto(ro, "short-id", p.Reality.ShortID)
			if p.Reality.SupportX25519MLKEM768 != nil {
				ro["support-x25519mlkem768"] = *p.Reality.SupportX25519MLKEM768
			}
			if len(ro) > 0 {
				m["reality-opts"] = ro
			}
		}
		switch p.Network {
		case "ws":
			wo := map[string]any{}
			setStrInto(wo, "path", p.Path)
			if p.Host != "" {
				wo["headers"] = map[string]any{"Host": p.Host}
			}
			if len(wo) > 0 {
				m["ws-opts"] = wo
			}
		case "grpc":
			if p.ServiceName != "" {
				m["grpc-opts"] = map[string]any{"grpc-service-name": p.ServiceName}
			}
		case "xhttp":
			xo := map[string]any{}
			setStrInto(xo, "path", p.Path)
			setStrInto(xo, "host", p.Host)
			setStrInto(xo, "mode", p.Mode)
			setStrInto(xo, "x-padding-bytes", p.XPaddingBytes)
			if len(xo) > 0 {
				m["xhttp-opts"] = xo
			}
		}

	case "hysteria2":
		setStr("password", p.Password)
		setStr("obfs", p.Obfs)
		setStr("obfs-password", p.ObfsPassword)
		// sni and skip-cert-verify are the two fields the panel never
		// emits; they were filled at parse time (or left as the link said).
		setStr("sni", p.ServerName)
		setBool("skip-cert-verify", p.SkipCertVerify)
		if len(p.ALPN) > 0 {
			m["alpn"] = p.ALPN
		}
		setStr("ports", p.Ports)
		setStr("up", p.Up)
		setStr("down", p.Down)
		if p.HopInterval != 0 {
			m["hop-interval"] = p.HopInterval
		}
		setBool("fast-open", p.FastOpen)

	case "trojan":
		setStr("password", p.Password)
		setStr("sni", p.ServerName)
		setStr("client-fingerprint", p.Fingerprint)
		if len(p.ALPN) > 0 {
			m["alpn"] = p.ALPN
		}
		setBool("skip-cert-verify", p.SkipCertVerify)
		setStr("network", p.Network)
		if p.Network == "ws" {
			wo := map[string]any{}
			setStrInto(wo, "path", p.Path)
			if p.Host != "" {
				wo["headers"] = map[string]any{"Host": p.Host}
			}
			if len(wo) > 0 {
				m["ws-opts"] = wo
			}
		}
		if p.Network == "grpc" && p.ServiceName != "" {
			m["grpc-opts"] = map[string]any{"grpc-service-name": p.ServiceName}
		}

	case "vmess":
		setStr("uuid", p.UUID)
		if p.AlterID != 0 {
			m["alterId"] = p.AlterID
		}
		setStr("cipher", p.Cipher)
		if p.TLS {
			m["tls"] = true
		}
		setStr("servername", p.ServerName)
		setStr("client-fingerprint", p.Fingerprint)
		setStr("network", p.Network)
		setStr("flow", p.Flow)
		if len(p.ALPN) > 0 {
			m["alpn"] = p.ALPN
		}
		setBool("skip-cert-verify", p.SkipCertVerify)
		if p.Network == "ws" {
			wo := map[string]any{}
			setStrInto(wo, "path", p.Path)
			if p.Host != "" {
				wo["headers"] = map[string]any{"Host": p.Host}
			}
			if len(wo) > 0 {
				m["ws-opts"] = wo
			}
		}
		if p.Network == "grpc" && p.ServiceName != "" {
			m["grpc-opts"] = map[string]any{"grpc-service-name": p.ServiceName}
		}

	case "ss":
		setStr("cipher", p.Method)
		setStr("password", p.Password)
		setStr("plugin", p.Plugin)
		setStr("plugin-opts", p.PluginOpts)

	default:
		return nil, fmt.Errorf("unsupported proxy type %q", p.Type)
	}
	return m, nil
}

func setStrInto(m map[string]any, k, v string) {
	if v != "" {
		m[k] = v
	}
}
