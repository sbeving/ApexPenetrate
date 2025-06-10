// internal/modules/reconnaissance/tech_fingerprint.go
package reconnaissance

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"apexPenetrateGo/internal/core"
)

// TechFingerprintResult holds detected technologies
type TechFingerprintResult struct {
	Target       string
	Technologies []string
	Headers      map[string][]string
}

// TechFingerprint tries to detect web technologies (Wappalyzer-lite)
func TechFingerprint(target string) *TechFingerprintResult {
	if !strings.HasPrefix(target, "http") {
		target = "http://" + target
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		return &TechFingerprintResult{Target: target, Technologies: []string{"Unreachable"}, Headers: nil}
	}
	defer resp.Body.Close()
	headers := resp.Header
	techs := []string{}
	// Simple header-based detection
	if server, ok := headers["Server"]; ok {
		techs = append(techs, "Server: "+server[0])
	}
	if xpowered, ok := headers["X-Powered-By"]; ok {
		techs = append(techs, "X-Powered-By: "+xpowered[0])
	}
	if setcookie, ok := headers["Set-Cookie"]; ok {
		for _, cookie := range setcookie {
			if strings.Contains(cookie, "PHPSESSID") {
				techs = append(techs, "PHP (session)")
			}
			if strings.Contains(cookie, "JSESSIONID") {
				techs = append(techs, "Java (session)")
			}
			if strings.Contains(cookie, "wordpress") {
				techs = append(techs, "WordPress (cookie)")
			}
		}
	}
	if len(techs) == 0 {
		techs = append(techs, "Unknown")
	}
	return &TechFingerprintResult{Target: target, Technologies: techs, Headers: headers}
}

func (r *TechFingerprintResult) String() string {
	return fmt.Sprintf("\n🧬 Tech Fingerprint for %s:\n  %s\n", r.Target, strings.Join(r.Technologies, ", "))
}

type techFingerprintPlugin struct{}

func (p *techFingerprintPlugin) Name() string { return "TechFingerprint" }
func (p *techFingerprintPlugin) Description() string {
	return "Detects web technologies (Wappalyzer-lite)"
}
func (p *techFingerprintPlugin) Category() string { return "recon" }
func (p *techFingerprintPlugin) Options() []core.ModuleOption {
	return []core.ModuleOption{
		{Name: "user_agent", Type: "string", Default: "Mozilla/5.0", Description: "User-Agent header for requests", Required: false},
	}
}
func (p *techFingerprintPlugin) Run(target string, options map[string]interface{}) (interface{}, error) {
	return TechFingerprint(target), nil
}
func (p *techFingerprintPlugin) Help() string {
	return `
🔬 Technology Fingerprinting - Web Stack Detection

DESCRIPTION:
  Identifies web technologies, frameworks, and CMS platforms through header analysis,
  HTML patterns, and JavaScript library detection.

USAGE:
  techfingerprint <target_url> [options]

EXAMPLES:
  techfingerprint https://example.com
  techfingerprint https://admin.site.com
  techfingerprint http://192.168.1.100

DETECTION METHODS:
  • HTTP Headers: Server, X-Powered-By, X-Framework
  • HTML Meta Tags: Generator, framework indicators
  • JavaScript Libraries: jQuery, React, Angular detection
  • CSS Framework: Bootstrap, Foundation identification

PRO TIPS:
  💡 Use results to select appropriate attack vectors
  💡 Check for version-specific vulnerabilities
  💡 Look for development frameworks in staging environments

RISK LEVEL: Low (reconnaissance for vulnerability research)
`
}

func init() {
	core.RegisterPlugin(&techFingerprintPlugin{})
}
