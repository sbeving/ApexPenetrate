// internal/modules/reconnaissance/reverse_ip.go
package reconnaissance

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"
)

// ReverseIPResult holds the results of a reverse IP lookup
type ReverseIPResult struct {
	IP      string
	Domains []string
	Source  string
}

// ReverseIPLookup queries a public API to find domains hosted on the same IP
func ReverseIPLookup(target string) (*ReverseIPResult, error) {
	// Resolve to IP if needed
	ip := target
	if net.ParseIP(target) == nil {
		ips, err := net.LookupIP(target)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("could not resolve %s to IP: %v", target, err)
		}
		ip = ips[0].String()
	}

	// Use HackerTarget API (no key required, public, rate-limited)
	url := fmt.Sprintf("https://api.hackertarget.com/reverseiplookup/?q=%s", ip)
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("reverse IP API error: %v", err)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	if strings.Contains(string(body), "error") {
		return nil, fmt.Errorf("reverse IP API error: %s", string(body))
	}
	lines := strings.Split(string(body), "\n")
	var domains []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.Contains(line, ip) {
			domains = append(domains, line)
		}
	}
	return &ReverseIPResult{
		IP:      ip,
		Domains: domains,
		Source:  "hackertarget.com",
	}, nil
}

// JSON helper for output
func (r *ReverseIPResult) ToJSON() string {
	data, _ := json.MarshalIndent(r, "", "  ")
	return string(data)
}
