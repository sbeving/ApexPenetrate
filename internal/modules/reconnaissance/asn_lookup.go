// internal/modules/reconnaissance/asn_lookup.go
package reconnaissance

import (
	"apexPenetrateGo/internal/core"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

type ASNLookupResult struct {
	IP          string
	ASN         string
	Org         string
	Country     string
	Network     string
	RawResponse string
}

func ASNLookup(target string) *ASNLookupResult {
	ip := target
	if net.ParseIP(target) == nil {
		ips, err := net.LookupIP(target)
		if err != nil || len(ips) == 0 {
			return &ASNLookupResult{IP: target, RawResponse: "Could not resolve IP"}
		}
		ip = ips[0].String()
	}
	url := fmt.Sprintf("https://ipinfo.io/%s/json", ip)
	client := &http.Client{Timeout: 6 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return &ASNLookupResult{IP: ip, RawResponse: "ipinfo.io error: " + err.Error()}
	}
	defer resp.Body.Close()
	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return &ASNLookupResult{IP: ip, RawResponse: "JSON decode error"}
	}
	as, _ := data["org"].(string)
	country, _ := data["country"].(string)
	network, _ := data["network"].(string)
	return &ASNLookupResult{
		IP:          ip,
		ASN:         as,
		Org:         as,
		Country:     country,
		Network:     network,
		RawResponse: fmt.Sprintf("%v", data),
	}
}

func (r *ASNLookupResult) String() string {
	if r.ASN == "" {
		return fmt.Sprintf("\n🌐 ASN Lookup for %s: %s", r.IP, r.RawResponse)
	}
	return fmt.Sprintf("\n🌐 ASN Lookup for %s:\n  ASN/Org: %s\n  Country: %s\n  Network: %s\n", r.IP, r.ASN, r.Country, r.Network)
}

type asnLookupPlugin struct{}

func (p *asnLookupPlugin) Name() string { return "ASNLookup" }
func (p *asnLookupPlugin) Description() string {
	return "Looks up ASN/Organization info for a target IP/domain"
}
func (p *asnLookupPlugin) Run(target string, options map[string]interface{}) (interface{}, error) {
	return ASNLookup(target), nil
}
func (p *asnLookupPlugin) Category() string { return "recon" }
func (p *asnLookupPlugin) Options() []core.ModuleOption {
	return []core.ModuleOption{
		{Name: "format", Type: "string", Default: "text", Description: "Output format (text, json)", Required: false},
	}
}

func init() {
	core.RegisterPlugin(&asnLookupPlugin{})
}
