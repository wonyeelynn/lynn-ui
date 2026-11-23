package converter

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// parseVMess parses a vmess:// link (base64-encoded JSON).
//
//	vmess://eyJ2IjoiMiIsInBzIjoiTmFtZSIsImFkZCI6Imhvc3QiLCJwb3J0IjoiNDQzIiwiaWQiOiJ1dWlkIiwiYWlkIjowLCJzY3kiOiJhdXRvIiwibmV0Ijoid3MiLCJ0eXBlIjoibm9uZSIsImhvc3QiOiIiLCJwYXRoIjoiL3dzIiwidGxzIjoidGxzIiwic25pIjoiIiwgImZwIjoiY2hyb21lIiwiYWxwbiI6ImgyIn0=
type vmessJSON struct {
	Version     string      `json:"v"`
	Name        string      `json:"ps"`
	Server      string      `json:"add"`
	Port        interface{} `json:"port"`
	UUID        string      `json:"id"`
	AlterID     int         `json:"aid"`
	Cipher      string      `json:"scy"`
	Network     string      `json:"net"`
	Type        string      `json:"type"`
	Host        string      `json:"host"`
	Path        string      `json:"path"`
	TLS         string      `json:"tls"`
	ServerName  string      `json:"sni"`
	Fingerprint string      `json:"fp"`
	ALPN        string      `json:"alpn"`
	Flow        string      `json:"flow"`
}

func parseVMess(link string) (*Proxy, error) {
	raw := strings.TrimPrefix(link, "vmess://")
	raw = strings.TrimSpace(raw)
	decoded, err := decodeB64(raw)
	if err != nil {
		return nil, fmt.Errorf("bad vmess link (base64): %w", err)
	}
	var v vmessJSON
	if err := json.Unmarshal(decoded, &v); err != nil {
		return nil, fmt.Errorf("bad vmess link (json): %w", err)
	}
	port := 0
	switch n := v.Port.(type) {
	case float64:
		port = int(n)
	case string:
		fmt.Sscanf(n, "%d", &port)
	}
	p := &Proxy{
		Name:        v.Name,
		Type:        "vmess",
		Server:      v.Server,
		Port:        port,
		UUID:        v.UUID,
		AlterID:     v.AlterID,
		Cipher:      v.Cipher,
		Raw:         link,
		UDP:         true,
		Flow:        v.Flow,
		Fingerprint: v.Fingerprint,
		ServerName:  v.ServerName,
		ALPN:        parseALPN(v.ALPN),
	}
	if v.TLS == "tls" {
		p.TLS = true
	}
	switch strings.ToLower(v.Network) {
	case "", "tcp":
		p.Network = "tcp"
	default:
		p.Network = strings.ToLower(v.Network)
	}
	p.Path = v.Path
	p.Host = v.Host
	return p, nil
}

// decodeB64 decodes base64 (standard or URL-safe, padded or not).
func decodeB64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	// Try standard, then URL-safe, adding padding as needed.
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	// Last resort: pad manually then try both alphabets.
	padded := s + strings.Repeat("=", (4-len(s)%4)%4)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		if b, err := enc.DecodeString(padded); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("cannot base64-decode %q", s)
}
