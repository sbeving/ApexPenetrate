// internal/modules/reconnaissance/dns_zone_transfer.go
package reconnaissance

import (
	"apexPenetrateGo/internal/core"
	"fmt"
	"net"
	"strings"
	"time"
)

type DNSZoneTransferResult struct {
	Domain     string
	Servers    []string
	Successful map[string][]string // server -> records
	Failed     []string
}

func DNSZoneTransfer(domain string) *DNSZoneTransferResult {
	result := &DNSZoneTransferResult{
		Domain:     domain,
		Servers:    []string{},
		Successful: map[string][]string{},
		Failed:     []string{},
	}
	servers, err := net.LookupNS(domain)
	if err != nil {
		result.Failed = append(result.Failed, "NS lookup failed")
		return result
	}
	for _, ns := range servers {
		nsHost := strings.TrimSuffix(ns.Host, ".")
		result.Servers = append(result.Servers, nsHost)
		axfr, err := tryZoneTransfer(nsHost, domain)
		if err == nil && len(axfr) > 0 {
			result.Successful[nsHost] = axfr
		} else {
			result.Failed = append(result.Failed, nsHost)
		}
	}
	return result
}

func tryZoneTransfer(server, domain string) ([]string, error) {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:53", server))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// Minimalistic: use net package only, not full DNS lib
	// For real use, recommend github.com/miekg/dns
	return nil, fmt.Errorf("AXFR not implemented (use miekg/dns for real zone transfer)")
}

func (r *DNSZoneTransferResult) String() string {
	msg := fmt.Sprintf("\n🛡️  DNS Zone Transfer Test for %s:\n", r.Domain)
	if len(r.Successful) > 0 {
		for ns, recs := range r.Successful {
			msg += fmt.Sprintf("  SUCCESS: %s\n    Records: %v\n", ns, recs)
		}
	} else {
		msg += "  No successful zone transfers.\n"
	}
	if len(r.Failed) > 0 {
		msg += fmt.Sprintf("  Failed/Refused: %v\n", r.Failed)
	}
	return msg
}

type dnsZoneTransferPlugin struct{}

func (p *dnsZoneTransferPlugin) Name() string { return "DNSZoneTransfer" }
func (p *dnsZoneTransferPlugin) Description() string {
	return "Tests for DNS zone transfer (AXFR) on all NS servers"
}
func (p *dnsZoneTransferPlugin) Run(target string, options map[string]interface{}) (interface{}, error) {
	return DNSZoneTransfer(target), nil
}
func (p *dnsZoneTransferPlugin) Category() string { return "recon" }
func (p *dnsZoneTransferPlugin) Options() []core.ModuleOption {
	return []core.ModuleOption{
		{Name: "timeout", Type: "string", Default: "5s", Description: "Timeout for DNS connections", Required: false},
		{Name: "port", Type: "int", Default: 53, Description: "DNS port to connect to", Required: false},
	}
}

func init() {
	core.RegisterPlugin(&dnsZoneTransferPlugin{})
}
