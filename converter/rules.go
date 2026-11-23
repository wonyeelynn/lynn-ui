// Rules merging: lynn-ui v0.2.0.
//
// The v0.1.0 output was proxies plus a minimal PROXY group only -- enough
// for clients that just take nodes (Shadowrocket), but clients that use the
// subscription as a complete configuration (Mihomo / Clash) lost the rule
// set and DNS the panel subscription used to carry. This file merges a
// rules document (proxy-groups, rule-providers, rules, dns) into the
// output, keeping lynn-ui's minimal PROXY group first so every rule group
// that references PROXY keeps working.
//
// Rules source: the file embedded here (rules.yaml) is a byte-identical
// copy of ~/workspace/vps-support/clash-rules-comprehensive.yaml -- the
// same file the panel's subClashRules points at on GitHub
// (wonyeelynn/3x-ui-rules). It is baked into the binary at build time so
// the deployed service has no runtime dependency on GitHub. Changing the
// rules means updating this copy, rebuilding, and redeploying -- the same
// verified-deploy discipline as any other change. The --rules flag also
// accepts a file path or an http(s) URL to override the embedded copy.
package converter

import (
	_ "embed"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed rules.yaml
var embeddedRulesYAML []byte

// EmbeddedRulesYAML returns the rules document baked into the binary.
func EmbeddedRulesYAML() []byte {
	return embeddedRulesYAML
}

// Rules is a parsed rules document: everything except proxies, which the
// merge owns.
type Rules struct {
	ProxyGroups   []map[string]any
	RuleProviders map[string]any
	Rules         []string
	DNS           map[string]any

	GroupCount    int
	ProviderCount int
	RuleCount     int
}

// builtinTargets are valid rule targets that are not proxy groups.
var builtinTargets = map[string]bool{
	"PROXY":  true, // lynn-ui's own minimal group, always emitted first
	"DIRECT": true, // Mihomo built-in
	"REJECT": true, // Mihomo built-in
}

// ruleFlags are trailing comma-separated flags on a rule line, not the
// target group (e.g. "DOMAIN-SUFFIX,example.com,Group,no-resolve").
var ruleFlags = map[string]bool{
	"no-resolve": true,
}

// ParseRules parses and validates a rules document. It rejects anything
// that would produce a broken merged document, so a bad rules file fails
// at startup (or at convert time) instead of shipping bad subscriptions.
func ParseRules(data []byte) (*Rules, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("bad rules YAML: %w", err)
	}
	if _, ok := doc["proxies"]; ok {
		return nil, fmt.Errorf("rules document must not define proxies")
	}

	r := &Rules{}

	groupsRaw, ok := doc["proxy-groups"]
	if !ok {
		return nil, fmt.Errorf("rules document has no proxy-groups")
	}
	groups, ok := groupsRaw.([]any)
	if !ok || len(groups) == 0 {
		return nil, fmt.Errorf("proxy-groups must be a non-empty list")
	}
	known := map[string]bool{}
	for i, g := range groups {
		m, ok := g.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("proxy-groups[%d] is not a mapping", i)
		}
		name, _ := m["name"].(string)
		if name == "" {
			return nil, fmt.Errorf("proxy-groups[%d] has no name", i)
		}
		if name == "PROXY" {
			return nil, fmt.Errorf("proxy-groups must not define a group named PROXY (lynn-ui owns it)")
		}
		if known[name] {
			return nil, fmt.Errorf("duplicate proxy-group %q", name)
		}
		known[name] = true
		r.ProxyGroups = append(r.ProxyGroups, m)
	}
	r.GroupCount = len(r.ProxyGroups)

	if raw, ok := doc["rule-providers"]; ok {
		m, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("rule-providers must be a mapping")
		}
		r.RuleProviders = m
	}
	r.ProviderCount = len(r.RuleProviders)

	rulesRaw, ok := doc["rules"]
	if !ok {
		return nil, fmt.Errorf("rules document has no rules")
	}
	rules, ok := rulesRaw.([]any)
	if !ok || len(rules) == 0 {
		return nil, fmt.Errorf("rules must be a non-empty list")
	}
	for i, item := range rules {
		line, ok := item.(string)
		if !ok || strings.TrimSpace(line) == "" {
			return nil, fmt.Errorf("rules[%d] is not a non-empty string", i)
		}
		line = strings.TrimSpace(line)
		r.Rules = append(r.Rules, line)
		if err := validateRule(line, known, r.RuleProviders); err != nil {
			return nil, fmt.Errorf("rules[%d] %q: %w", i, line, err)
		}
	}
	r.RuleCount = len(r.Rules)

	if raw, ok := doc["dns"]; ok {
		m, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("dns must be a mapping")
		}
		r.DNS = m
	}
	return r, nil
}

// validateRule checks one rule line: its target group must exist (a merged
// proxy group or a built-in), and a RULE-SET provider must exist.
func validateRule(line string, groups map[string]bool, providers map[string]any) error {
	fields := strings.Split(line, ",")
	// Strip trailing flags; the last remaining field is the target group.
	for len(fields) > 0 && ruleFlags[strings.TrimSpace(fields[len(fields)-1])] {
		fields = fields[:len(fields)-1]
	}
	if len(fields) < 2 {
		return fmt.Errorf("rule has too few fields")
	}
	kind := strings.TrimSpace(fields[0])
	target := strings.TrimSpace(fields[len(fields)-1])
	if target == "" {
		return fmt.Errorf("rule has no target group")
	}
	if kind == "RULE-SET" {
		if len(fields) < 3 {
			return fmt.Errorf("RULE-SET rule has too few fields")
		}
		provider := strings.TrimSpace(fields[1])
		if _, ok := providers[provider]; !ok {
			return fmt.Errorf("unknown rule provider %q", provider)
		}
	}
	if !groups[target] && !builtinTargets[target] {
		return fmt.Errorf("unknown target group %q", target)
	}
	return nil
}

// LoadRulesFromSource loads a rules document from "embedded", a local file
// path, or an http(s) URL, and parses + validates it.
func LoadRulesFromSource(src string) (*Rules, error) {
	var data []byte
	switch {
	case src == "embedded":
		data = embeddedRulesYAML
	case strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://"):
		body, err := FetchSubscription(src)
		if err != nil {
			return nil, fmt.Errorf("fetch rules %q: %w", src, err)
		}
		data = []byte(body)
	default:
		b, err := os.ReadFile(src)
		if err != nil {
			return nil, fmt.Errorf("read rules %q: %w", src, err)
		}
		data = b
	}
	return ParseRules(data)
}
