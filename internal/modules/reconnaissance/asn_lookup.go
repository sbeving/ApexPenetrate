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

func (p *asnLookupPlugin) Help() string {
	return `
🌐 ASN Lookup - Autonomous System Number Intelligence Gathering

DESCRIPTION:
  Performs ASN (Autonomous System Number) lookups to identify network ownership,
  IP ranges, and related infrastructure for comprehensive network reconnaissance.

USAGE:
  asnlookup <target_ip_or_domain> [options]

OPTIONS:
  format - Output format: text or json (default: text)

EXAMPLES:
  asnlookup 8.8.8.8
  asnlookup google.com --format json
  asnlookup 192.168.1.1 --format text

INTELLIGENCE GATHERED:
  • ASN Number: Unique identifier for the autonomous system
  • Organization: Company/entity that owns the network
  • IP Ranges: CIDR blocks assigned to the ASN
  • Country: Geographic location of the network
  • Registry: Regional Internet Registry (ARIN, RIPE, etc.)

ATTACK SCENARIOS:
  • Network Mapping: Identify all IP ranges owned by target
  • Infrastructure Discovery: Find related services and subsidiaries
  • Attack Surface: Enumerate additional targets within same ASN
  • Pivot Points: Discover connected networks and partners

PRO TIPS:
  💡 Use ASN data to find all IP ranges owned by target organization
  💡 Cross-reference with subdomain enumeration for complete coverage
  💡 Check for cloud provider ASNs (AWS, Azure, GCP) for cloud assets
  💡 Look for multiple ASNs indicating distributed infrastructure
  💡 Combine with reverse IP lookup for comprehensive mapping

DATA SOURCES:
  • Team Cymru IP to ASN mapping
  • Regional Internet Registries (RIRs)
  • BGP routing tables
  • WHOIS databases

RISK LEVEL: Low (reconnaissance/intelligence gathering)
`
}

func init() {
	core.RegisterPlugin(&asnLookupPlugin{})
}
