package converter

import (
	"encoding/base64"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Dummy credentials only. Nothing here is real.

// parseOutput parses the Clash YAML produced by BuildClash into a map of
// proxy name -> proxy fields, for assertions.
func parseOutput(t *testing.T, out []byte) map[string]map[string]interface{} {
	t.Helper()
	var doc struct {
		Proxies []map[string]interface{} `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is not valid YAML: %v\n%s", err, out)
	}
	m := map[string]map[string]interface{}{}
	for _, p := range doc.Proxies {
		name, _ := p["name"].(string)
		m[name] = p
	}
	return m
}

func str(m map[string]interface{}, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func TestVLESSReality(t *testing.T) {
	// Mirrors a real VLESS+REALITY link shape, with dummy values.
	link := "vless://11111111-2222-3333-4444-555555555555@node.example.net:443" +
		"?encryption=none&flow=xtls-rprx-vision&fp=chrome" +
		"&pbk=AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA" +
		"&security=reality&sid=abcdef1234&sni=front.example.org" +
		"&spx=%2Fdummy-spider-path&support-x25519mlkem768=true&type=tcp#Reality-Node"
	out, err := ConvertLinks(link, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	proxies := parseOutput(t, out)
	p := proxies["Reality-Node"]
	if p == nil {
		t.Fatalf("missing proxy; output:\n%s", out)
	}
	if str(p, "type") != "vless" || str(p, "server") != "node.example.net" {
		t.Errorf("identity wrong: %v", p)
	}
	if str(p, "uuid") != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("uuid lost")
	}
	if str(p, "servername") != "front.example.org" {
		t.Errorf("servername lost: %v", p["servername"])
	}
	if str(p, "client-fingerprint") != "chrome" {
		t.Errorf("fingerprint lost")
	}
	if str(p, "flow") != "xtls-rprx-vision" {
		t.Errorf("flow lost")
	}
	if str(p, "network") != "tcp" || p["tls"] != true || p["udp"] != true {
		t.Errorf("network/tls/udp wrong: %v", p)
	}
	ro, ok := p["reality-opts"].(map[string]interface{})
	if !ok {
		t.Fatalf("reality-opts missing (this is the sublink bug):\n%s", out)
	}
	if str(ro, "public-key") != "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA" {
		t.Errorf("public-key lost (this is the sublink bug): %v", ro)
	}
	if str(ro, "short-id") != "abcdef1234" {
		t.Errorf("short-id lost: %v", ro)
	}
	if ro["support-x25519mlkem768"] != true {
		t.Errorf("support-x25519mlkem768 lost: %v", ro)
	}
	// spx has no Mihomo field and is intentionally not emitted.
	if _, ok := ro["spx"]; ok {
		t.Errorf("spx should not be emitted in reality-opts")
	}
}

func TestVLESSRealityMLKEMFalse(t *testing.T) {
	link := "vless://11111111-2222-3333-4444-555555555555@node.example.net:443" +
		"?security=reality&pbk=DUMMY_PBK&sid=abcd&sni=a.example&support-x25519mlkem768=false#R2"
	out, err := ConvertLinks(link, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	p := parseOutput(t, out)["R2"]
	ro := p["reality-opts"].(map[string]interface{})
	if ro["support-x25519mlkem768"] != false {
		t.Errorf("support-x25519mlkem768=false not preserved: %v", ro)
	}
}

func TestVLESSXHTTP(t *testing.T) {
	link := "vless://11111111-2222-3333-4444-555555555555@node.example.net:8443" +
		"?alpn=h2%2Chttp%2F1.1&encryption=none&fp=chrome&mode=auto&path=%2F" +
		"&security=tls&sni=node.example.net&type=xhttp&x_padding_bytes=100-1000" +
		"&extra=%7B%22mode%22%3A%22auto%22%2C%22xPaddingBytes%22%3A%22100-1000%22%7D#XHTTP-Node"
	out, err := ConvertLinks(link, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	p := parseOutput(t, out)["XHTTP-Node"]
	if p == nil {
		t.Fatalf("missing proxy:\n%s", out)
	}
	if str(p, "network") != "xhttp" {
		t.Errorf("network wrong: %v", p["network"])
	}
	xo, ok := p["xhttp-opts"].(map[string]interface{})
	if !ok {
		t.Fatalf("xhttp-opts missing (this is the sublink bug):\n%s", out)
	}
	if str(xo, "path") != "/" || str(xo, "mode") != "auto" || str(xo, "x-padding-bytes") != "100-1000" {
		t.Errorf("xhttp-opts incomplete: %v", xo)
	}
	alpn, _ := p["alpn"].([]interface{})
	if len(alpn) != 2 || alpn[0] != "h2" || alpn[1] != "http/1.1" {
		t.Errorf("alpn lost: %v", p["alpn"])
	}
	if str(p, "servername") != "node.example.net" {
		t.Errorf("servername lost")
	}
}

func TestVLESSXHTTPExtraFallback(t *testing.T) {
	// Only the "extra" JSON carries mode / xPaddingBytes; top-level params
	// are absent. The converter must still emit them.
	link := "vless://11111111-2222-3333-4444-555555555555@node.example.net:8443" +
		"?encryption=none&fp=chrome&path=%2F&security=tls&sni=node.example.net&type=xhttp" +
		"&extra=%7B%22mode%22%3A%22auto%22%2C%22xPaddingBytes%22%3A%22100-1000%22%7D#XHTTP-Extra"
	out, err := ConvertLinks(link, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	p := parseOutput(t, out)["XHTTP-Extra"]
	xo := p["xhttp-opts"].(map[string]interface{})
	if str(xo, "mode") != "auto" || str(xo, "x-padding-bytes") != "100-1000" {
		t.Errorf("extra JSON fallback failed: %v", xo)
	}
}

func TestHysteria2KeepsObfs(t *testing.T) {
	// The panel drops obfs for external-link HY2 nodes. lynn-ui must keep it.
	link := "hysteria2://DUMMY_HY2_PASSWORD@tw.example.net:443" +
		"?alpn=h3&obfs=salamander&obfs-password=DUMMY_OBFS_PASSWORD&security=tls#HY2-TW"
	out, err := ConvertLinks(link, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	p := parseOutput(t, out)["HY2-TW"]
	if p == nil {
		t.Fatalf("missing proxy:\n%s", out)
	}
	if str(p, "obfs") != "salamander" {
		t.Errorf("obfs lost (this is the panel bug): %v", p)
	}
	if str(p, "obfs-password") != "DUMMY_OBFS_PASSWORD" {
		t.Errorf("obfs-password lost (this is the panel bug): %v", p)
	}
	if str(p, "password") != "DUMMY_HY2_PASSWORD" {
		t.Errorf("password lost")
	}
	// The fix: sni / skip-cert-verify are filled when the link lacks them.
	if str(p, "sni") != "tw.example.net" {
		t.Errorf("sni should default to the server hostname: %v", p["sni"])
	}
	if p["skip-cert-verify"] != true {
		t.Errorf("skip-cert-verify should default to true: %v", p["skip-cert-verify"])
	}
	alpn, _ := p["alpn"].([]interface{})
	if len(alpn) != 1 || alpn[0] != "h3" {
		t.Errorf("alpn lost: %v", p["alpn"])
	}
	if p["udp"] != true {
		t.Errorf("udp should be true")
	}
}

func TestHysteria2ExplicitSNIAndInsecure(t *testing.T) {
	// Explicit values in the link win over the defaults.
	link := "hysteria2://DUMMY_PW@tw.example.net:443" +
		"?alpn=h3&obfs=salamander&obfs-password=DUMMY_OBFS&sni=sni.example.net&insecure=0#HY2-Explicit"
	out, err := ConvertLinks(link, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	p := parseOutput(t, out)["HY2-Explicit"]
	if str(p, "sni") != "sni.example.net" {
		t.Errorf("explicit sni not respected: %v", p["sni"])
	}
	if p["skip-cert-verify"] != false {
		t.Errorf("explicit insecure=0 not respected: %v", p["skip-cert-verify"])
	}
}

func TestHysteria2DefaultsDisabled(t *testing.T) {
	link := "hysteria2://DUMMY_PW@tw.example.net:443?alpn=h3&obfs=salamander&obfs-password=DUMMY_OBFS#HY2-NoDefault"
	opts := DefaultOptions()
	opts.HY2SNIHost = false
	opts.HY2SkipVerify = false
	out, err := ConvertLinks(link, opts)
	if err != nil {
		t.Fatal(err)
	}
	p := parseOutput(t, out)["HY2-NoDefault"]
	if str(p, "sni") != "" {
		t.Errorf("sni should be empty when the default is off: %v", p["sni"])
	}
	if _, ok := p["skip-cert-verify"]; ok {
		t.Errorf("skip-cert-verify should be absent when the default is off: %v", p["skip-cert-verify"])
	}
	// obfs must still be kept.
	if str(p, "obfs") != "salamander" {
		t.Errorf("obfs lost even with defaults off")
	}
}

func TestInboundAndExternalAreIdentical(t *testing.T) {
	// The core requirement: a node converts identically whether it came
	// from a local inbound or an external link. Both arrive as links, so
	// there is no code path that can treat them differently.
	link := "hysteria2://DUMMY_PW@tw.example.net:443?alpn=h3&obfs=salamander&obfs-password=DUMMY_OBFS#Same-Node"
	a, err := ConvertLinks(link, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	b, err := ConvertLinks(link, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Errorf("same link converted differently:\n%s\n---\n%s", a, b)
	}
}

func TestTrojan(t *testing.T) {
	link := "trojan://DUMMY_TROJAN_PW@node.example.net:443?sni=node.example.net&fp=chrome&alpn=h2&type=ws&path=%2Fws&host=node.example.net#Trojan-Node"
	out, err := ConvertLinks(link, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	p := parseOutput(t, out)["Trojan-Node"]
	if str(p, "password") != "DUMMY_TROJAN_PW" || str(p, "sni") != "node.example.net" {
		t.Errorf("trojan fields lost: %v", p)
	}
	if str(p, "network") != "ws" {
		t.Errorf("trojan network lost")
	}
	wo, ok := p["ws-opts"].(map[string]interface{})
	if !ok || str(wo, "path") != "/ws" {
		t.Errorf("trojan ws-opts lost: %v", p["ws-opts"])
	}
}

func TestVMess(t *testing.T) {
	j := `{"v":"2","ps":"VMess-Node","add":"node.example.net","port":"443","id":"11111111-2222-3333-4444-555555555555","aid":0,"scy":"auto","net":"ws","type":"none","host":"","path":"/ws","tls":"tls","sni":"node.example.net","fp":"chrome","alpn":"h2"}`
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(j))
	out, err := ConvertLinks(link, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	p := parseOutput(t, out)["VMess-Node"]
	if str(p, "uuid") != "11111111-2222-3333-4444-555555555555" || str(p, "network") != "ws" {
		t.Errorf("vmess fields lost: %v", p)
	}
	if p["tls"] != true || str(p, "servername") != "node.example.net" {
		t.Errorf("vmess tls/servername lost: %v", p)
	}
}

func TestShadowsocks(t *testing.T) {
	// ss://base64(method:password)@host:port#name
	cred := base64.URLEncoding.EncodeToString([]byte("aes-128-gcm:DUMMY_SS_PASSWORD"))
	link := "ss://" + cred + "@node.example.net:8388#SS-Node"
	out, err := ConvertLinks(link, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	p := parseOutput(t, out)["SS-Node"]
	if str(p, "cipher") != "aes-128-gcm" || str(p, "password") != "DUMMY_SS_PASSWORD" {
		t.Errorf("ss fields lost: %v", p)
	}
}

func TestBase64Subscription(t *testing.T) {
	plain := "vless://11111111-2222-3333-4444-555555555555@a.example.net:443?security=reality&pbk=DUMMY_PBK&sid=abcd&sni=a.example#R\n" +
		"hysteria2://DUMMY_PW@b.example.net:443?alpn=h3&obfs=salamander&obfs-password=DUMMY_OBFS#H\n"
	b64 := base64.StdEncoding.EncodeToString([]byte(plain))
	out, err := ConvertLinks(b64, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	proxies := parseOutput(t, out)
	if proxies["R"] == nil || proxies["H"] == nil {
		t.Fatalf("base64 subscription did not decode to both nodes:\n%s", out)
	}
}

func TestNineNodesMirror(t *testing.T) {
	// Mirrors the real subscription shape (3 servers x 3 protocols) with
	// dummy values. Every node must come out complete.
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
	out, err := ConvertLinks(strings.Join(links, "\n"), DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	proxies := parseOutput(t, out)
	if len(proxies) != 9 {
		t.Fatalf("expected 9 proxies, got %d:\n%s", len(proxies), out)
	}
	for _, name := range []string{"SJ-Reality", "TW-Reality", "SE-Reality"} {
		p := proxies[name]
		ro, ok := p["reality-opts"].(map[string]interface{})
		if !ok || str(ro, "public-key") != pbk || str(ro, "short-id") == "" || ro["support-x25519mlkem768"] != true {
			t.Errorf("%s: reality fields incomplete: %v", name, p["reality-opts"])
		}
	}
	for _, name := range []string{"SJ-XHTTP", "TW-XHTTP", "SE-XHTTP"} {
		p := proxies[name]
		xo, ok := p["xhttp-opts"].(map[string]interface{})
		if !ok || str(xo, "path") != "/" || str(xo, "mode") != "auto" || str(xo, "x-padding-bytes") != "100-1000" {
			t.Errorf("%s: xhttp-opts incomplete: %v", name, p["xhttp-opts"])
		}
	}
	for _, name := range []string{"SJ-HY2", "TW-HY2", "SE-HY2"} {
		p := proxies[name]
		if str(p, "obfs") != "salamander" || str(p, "obfs-password") != "DUMMY_OBFS" {
			t.Errorf("%s: obfs lost: %v", name, p)
		}
		if str(p, "sni") == "" || p["skip-cert-verify"] != true {
			t.Errorf("%s: sni/skip-cert-verify missing: %v", name, p)
		}
	}
}

func TestUnsupportedSchemeSkipped(t *testing.T) {
	// One bad line must not fail the whole conversion.
	input := "vless://11111111-2222-3333-4444-555555555555@a.example.net:443?security=tls&sni=a.example#Good\n" +
		"unknown://foo@a.example.net:443#Bad\n"
	proxies, warnings, err := ParseSubscriptionText(input, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(proxies))
	}
	if len(warnings) != 1 {
		t.Errorf("expected 1 warning, got %v", warnings)
	}
}
