package converter

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Dummy rules only. Nothing here is real.

const testRulesYAML = `
proxy-groups:
- name: Streaming
  type: select
  proxies: [PROXY, DIRECT]
  include-all-proxies: true
- name: Ads
  type: select
  proxies: [PROXY, REJECT]
  include-all-proxies: true
rule-providers:
  streaming:
    type: http
    behavior: domain
    url: "https://example.com/streaming.yaml"
    path: ./rules/streaming.yaml
    interval: 86400
  ads:
    type: http
    behavior: domain
    url: "https://example.com/ads.yaml"
    path: ./rules/ads.yaml
    interval: 86400
rules:
- DOMAIN-SUFFIX,netflix.com,Streaming
- DOMAIN-KEYWORD,ads,Ads
- RULE-SET,streaming,Streaming
- RULE-SET,ads,Ads,no-resolve
- GEOIP,CN,DIRECT
- MATCH,Streaming
dns:
  enable: true
  ipv6: false
  nameserver:
  - 223.5.5.5
  - 8.8.8.8
`

func TestParseRulesBasic(t *testing.T) {
	r, err := ParseRules([]byte(testRulesYAML))
	if err != nil {
		t.Fatal(err)
	}
	if r.GroupCount != 2 || r.ProviderCount != 2 || r.RuleCount != 6 {
		t.Errorf("counts wrong: groups=%d providers=%d rules=%d", r.GroupCount, r.ProviderCount, r.RuleCount)
	}
	if r.DNS == nil {
		t.Errorf("dns missing")
	}
}

func TestBuildClashWithRules(t *testing.T) {
	r, err := ParseRules([]byte(testRulesYAML))
	if err != nil {
		t.Fatal(err)
	}
	link := "vless://11111111-2222-3333-4444-555555555555@node.example.net:443?security=tls&sni=node.example.net#Node"
	proxies, _, err := ParseSubscriptionText(link, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	out, err := BuildClashWithRules(proxies, r)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Proxies       []map[string]interface{} `yaml:"proxies"`
		ProxyGroups   []map[string]interface{} `yaml:"proxy-groups"`
		RuleProviders map[string]interface{}   `yaml:"rule-providers"`
		Rules         []string                 `yaml:"rules"`
		DNS           map[string]interface{}   `yaml:"dns"`
	}
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is not valid YAML: %v\n%s", err, out)
	}
	if len(doc.Proxies) != 1 {
		t.Errorf("expected 1 proxy, got %d", len(doc.Proxies))
	}
	if len(doc.ProxyGroups) != 3 {
		t.Fatalf("expected 3 proxy-groups (PROXY + 2), got %d:\n%s", len(doc.ProxyGroups), out)
	}
	if doc.ProxyGroups[0]["name"] != "PROXY" {
		t.Errorf("first group must be PROXY, got %v", doc.ProxyGroups[0]["name"])
	}
	if doc.ProxyGroups[1]["name"] != "Streaming" || doc.ProxyGroups[2]["name"] != "Ads" {
		t.Errorf("rules groups not appended in order: %v", doc.ProxyGroups)
	}
	if len(doc.RuleProviders) != 2 {
		t.Errorf("expected 2 rule-providers, got %d", len(doc.RuleProviders))
	}
	if len(doc.Rules) != 6 {
		t.Errorf("expected 6 rules, got %d", len(doc.Rules))
	}
	if doc.DNS == nil || doc.DNS["enable"] != true {
		t.Errorf("dns missing or wrong: %v", doc.DNS)
	}
	// A rule group referencing PROXY must resolve: PROXY is group 0.
	if doc.ProxyGroups[1]["proxies"] == nil {
		t.Errorf("Streaming group lost its proxies list")
	}
}

func TestBuildClashWithoutRulesUnchanged(t *testing.T) {
	// No rules: output must stay proxies + the single PROXY group.
	link := "vless://11111111-2222-3333-4444-555555555555@node.example.net:443?security=tls&sni=node.example.net#Node"
	out, err := ConvertLinks(link, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		ProxyGroups   []map[string]interface{} `yaml:"proxy-groups"`
		RuleProviders map[string]interface{}   `yaml:"rule-providers"`
		Rules         []string                 `yaml:"rules"`
		DNS           map[string]interface{}   `yaml:"dns"`
	}
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.ProxyGroups) != 1 || doc.ProxyGroups[0]["name"] != "PROXY" {
		t.Errorf("pure output must have only the PROXY group: %v", doc.ProxyGroups)
	}
	if doc.RuleProviders != nil || doc.Rules != nil || doc.DNS != nil {
		t.Errorf("pure output must not carry rules sections")
	}
}

func TestConvertLinksWithRules(t *testing.T) {
	r, err := ParseRules([]byte(testRulesYAML))
	if err != nil {
		t.Fatal(err)
	}
	opts := DefaultOptions()
	opts.Rules = r
	link := "hysteria2://DUMMY_PW@tw.example.net:443?alpn=h3&obfs=salamander&obfs-password=DUMMY_OBFS#HY2"
	out, err := ConvertLinks(link, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "rule-providers:") || !strings.Contains(string(out), "MATCH,Streaming") {
		t.Errorf("merged output missing rules sections:\n%s", out)
	}
	if !strings.Contains(string(out), "obfs: salamander") {
		t.Errorf("merged output lost the node fields:\n%s", out)
	}
}

func TestParseRulesRejectsDuplicatePROXY(t *testing.T) {
	bad := `
proxy-groups:
- name: PROXY
  type: select
  proxies: [DIRECT]
rules:
- MATCH,PROXY
`
	if _, err := ParseRules([]byte(bad)); err == nil {
		t.Errorf("a rules group named PROXY must be rejected")
	}
}

func TestParseRulesRejectsMissingGroup(t *testing.T) {
	bad := `
proxy-groups:
- name: Streaming
  type: select
  proxies: [PROXY]
rules:
- DOMAIN-SUFFIX,example.com,NoSuchGroup
`
	if _, err := ParseRules([]byte(bad)); err == nil {
		t.Errorf("a rule pointing at a missing group must be rejected")
	}
}

func TestParseRulesRejectsMissingProvider(t *testing.T) {
	bad := `
proxy-groups:
- name: Streaming
  type: select
  proxies: [PROXY]
rule-providers:
  streaming:
    type: http
    behavior: domain
    url: "https://example.com/x.yaml"
    path: ./rules/x.yaml
    interval: 86400
rules:
- RULE-SET,missing-provider,Streaming
`
	if _, err := ParseRules([]byte(bad)); err == nil {
		t.Errorf("a RULE-SET pointing at a missing provider must be rejected")
	}
}

func TestParseRulesRejectsProxiesSection(t *testing.T) {
	bad := `
proxies:
- name: X
  type: vless
  server: x.example.net
  port: 443
proxy-groups:
- name: Streaming
  type: select
  proxies: [PROXY]
rules:
- MATCH,Streaming
`
	if _, err := ParseRules([]byte(bad)); err == nil {
		t.Errorf("a rules document defining proxies must be rejected")
	}
}

func TestParseRulesAcceptsNoResolveFlag(t *testing.T) {
	// Trailing ",no-resolve" is a flag, not the target group.
	r, err := ParseRules([]byte(testRulesYAML))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range r.Rules {
		if strings.HasSuffix(line, ",no-resolve") && !strings.Contains(line, "RULE-SET,ads,Ads,no-resolve") {
			t.Errorf("unexpected no-resolve rule: %q", line)
		}
	}
}

func TestEmbeddedRules(t *testing.T) {
	// The copy baked into the binary must be the real 19-group file and
	// must merge cleanly with a 9-node subscription.
	r, err := ParseRules(EmbeddedRulesYAML())
	if err != nil {
		t.Fatalf("embedded rules do not parse: %v", err)
	}
	if r.GroupCount != 19 || r.ProviderCount != 45 || r.RuleCount != 48 {
		t.Errorf("embedded rules counts wrong: groups=%d providers=%d rules=%d (want 19/45/48)",
			r.GroupCount, r.ProviderCount, r.RuleCount)
	}
	if r.DNS == nil {
		t.Errorf("embedded rules missing dns")
	}

	uuid := "11111111-2222-3333-4444-555555555555"
	pbk := "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
	links := []string{
		"vless://" + uuid + "@sj.example.net:443?encryption=none&flow=xtls-rprx-vision&fp=chrome&pbk=" + pbk + "&security=reality&sid=aaaa1111&sni=front.example.org&support-x25519mlkem768=true&type=tcp#SJ-Reality",
		"vless://" + uuid + "@sj.example.net:8443?alpn=h2%2Chttp%2F1.1&encryption=none&fp=chrome&mode=auto&path=%2F&security=tls&sni=sj.example.net&type=xhttp&x_padding_bytes=100-1000#SJ-XHTTP",
		"hysteria2://DUMMY_HY2_PW@sj.example.net:443?alpn=h3&obfs=salamander&obfs-password=DUMMY_OBFS#SJ-HY2",
		"vless://" + uuid + "@tw.example.net:443?encryption=none&flow=xtls-rprx-vision&fp=chrome&pbk=" + pbk + "&security=reality&sid=bbbb2222&sni=front.example.org&support-x25519mlkem768=true&type=tcp#TW-Reality",
		"vless://" + uuid + "@tw.example.net:8443?alpn=h2%2Chttp%2F1.1&encryption=none&fp=chrome&mode=auto&path=%2F&security=tls&sni=tw.example.net&type=xhttp&x_padding_bytes=100-1000#TW-XHTTP",
		"hysteria2://DUMMY_HY2_PW@tw.example.net:443?alpn=h3&obfs=salamander&obfs-password=DUMMY_OBFS#TW-HY2",
		"vless://" + uuid + "@se.example.net:443?encryption=none&flow=xtls-rprx-vision&fp=chrome&pbk=" + pbk + "&security=reality&sid=cccc3333&sni=front.example.org&support-x25519mlkem768=true&type=tcp#SE-Reality",
		"vless://" + uuid + "@se.example.net:8443?alpn=h2%2Chttp%2F1.1&encryption=none&fp=chrome&mode=auto&path=%2F&security=tls&sni=se.example.net&type=xhttp&x_padding_bytes=100-1000#SE-XHTTP",
		"hysteria2://DUMMY_HY2_PW@se.example.net:443?alpn=h3&obfs=salamander&obfs-password=DUMMY_OBFS#SE-HY2",
	}
	opts := DefaultOptions()
	opts.Rules = r
	out, err := ConvertLinks(strings.Join(links, "\n"), opts)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Proxies       []map[string]interface{} `yaml:"proxies"`
		ProxyGroups   []map[string]interface{} `yaml:"proxy-groups"`
		RuleProviders map[string]interface{}   `yaml:"rule-providers"`
		Rules         []string                 `yaml:"rules"`
		DNS           map[string]interface{}   `yaml:"dns"`
	}
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("merged output is not valid YAML: %v\n%s", err, out)
	}
	if len(doc.Proxies) != 9 {
		t.Errorf("expected 9 proxies, got %d", len(doc.Proxies))
	}
	if len(doc.ProxyGroups) != 20 {
		t.Errorf("expected 20 proxy-groups (PROXY + 19), got %d", len(doc.ProxyGroups))
	}
	if len(doc.RuleProviders) != 45 {
		t.Errorf("expected 45 rule-providers, got %d", len(doc.RuleProviders))
	}
	if len(doc.Rules) != 48 {
		t.Errorf("expected 48 rules, got %d", len(doc.Rules))
	}
	if doc.DNS == nil {
		t.Errorf("merged output missing dns")
	}
	// Nodes must stay complete after the merge.
	byName := map[string]map[string]interface{}{}
	for _, p := range doc.Proxies {
		if n, ok := p["name"].(string); ok {
			byName[n] = p
		}
	}
	for _, name := range []string{"SJ-Reality", "TW-Reality", "SE-Reality"} {
		ro, ok := byName[name]["reality-opts"].(map[string]interface{})
		if !ok || ro["public-key"] != pbk {
			t.Errorf("%s: reality public-key lost after merge", name)
		}
	}
	for _, name := range []string{"SJ-HY2", "TW-HY2", "SE-HY2"} {
		if byName[name]["obfs"] != "salamander" || byName[name]["skip-cert-verify"] != true {
			t.Errorf("%s: HY2 fields lost after merge: %v", name, byName[name])
		}
	}
}
