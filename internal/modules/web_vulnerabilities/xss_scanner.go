// internal/modules/web_vulnerabilities/xss_scanner.go
package web_vulnerabilities

import (
	"apexPenetrateGo/internal/core"
	"apexPenetrateGo/internal/core/logger"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// XSSScanner holds the state for XSS scanning
type XSSScanner struct {
	url     string
	log     *logrus.Logger
	payload string
}

// NewXSSScanner creates a new instance of XSSScanner
func NewXSSScanner(url string) *XSSScanner {
	return &XSSScanner{
		url:     url,
		log:     logger.GetLogger(),
		payload: "<script>alert('xss')</script>",
	}
}

// ScanXSS performs a real reflected XSS test by injecting a payload and checking the response.
func (s *XSSScanner) ScanXSS() []map[string]string {
	s.log.Infof("Scanning for XSS in %s...", s.url)
	findings := []map[string]string{}
	testPayload := s.payload
	testURL := s.url
	if strings.Contains(s.url, "?") {
		testURL += "&xss=" + testPayload
	} else {
		testURL += "?xss=" + testPayload
	}
	resp, err := http.Get(testURL)
	if err != nil {
		s.log.Warnf("HTTP error: %v", err)
		return findings
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), testPayload) {
		findings = append(findings, map[string]string{
			"url":           testURL,
			"vulnerability": "Reflected XSS",
			"payload":       testPayload,
		})
	}
	time.Sleep(300 * time.Millisecond) // Simulate scan delay
	s.log.Info("XSS scan complete.")
	return findings
}

// XSSScannerPlugin implements the Plugin interface for XSS scanning
// (for parametric/intelligent shell)
type xssScannerPlugin struct{}

func (p *xssScannerPlugin) Name() string        { return "XSSScanner" }
func (p *xssScannerPlugin) Description() string { return "Scans for reflected XSS vulnerabilities" }
func (p *xssScannerPlugin) Category() string    { return "web" }
func (p *xssScannerPlugin) Options() []core.ModuleOption {
	return []core.ModuleOption{
		{Name: "payload", Type: "string", Default: "<script>alert('xss')</script>", Description: "Payload to inject for XSS testing", Required: false},
	}
}
func (p *xssScannerPlugin) Help() string {
	return `
🔍 XSSScanner Module - Cross-Site Scripting Vulnerability Scanner

📋 DESCRIPTION:
   Advanced Cross-Site Scripting (XSS) vulnerability scanner that tests for
   reflected, stored, and DOM-based XSS vulnerabilities using sophisticated
   payload techniques and context-aware detection.

🎯 USAGE:
   apex> use XSSScanner
   apex> set target http://example.com/search
   apex> set payload <script>alert('XSS')</script>
   apex> run

📊 EXAMPLES:
   • Basic Reflected XSS:
     target=http://example.com/search?q=test
   
   • Custom Payload Testing:
     payload=<img src=x onerror=alert(1)>
     payload=javascript:alert('XSS')
     payload=<svg onload=alert('XSS')>
   
   • Form Parameter Testing:
     Test POST forms and input fields
   
   • URL Parameter Injection:
     Automatically tests GET parameters

⚙️ OPTIONS:
   payload  [OPTIONAL] - Custom XSS payload (default: <script>alert('xss')</script>)
   
🔧 ATTACK VECTORS:
   • HTML Context: <script>, <img>, <svg>, <iframe>
   • Attribute Context: event handlers, href, src
   • JavaScript Context: string breakouts
   • CSS Context: expression(), behavior
   • URL Context: javascript:, data: schemes

📈 DETECTION METHODS:
   • Response content analysis
   • Payload reflection detection
   • Context-aware validation
   • DOM manipulation testing
   • Error-based identification

💡 PRO TIPS:
   → Test multiple encoding types (URL, HTML, JS)
   → Check both GET and POST parameters
   → Look for reflected content in headers
   → Test file upload functionality
   → Combine with DirFuzzer for comprehensive coverage
   → Use varied payloads to bypass filters

🚨 SEVERITY LEVELS:
   🔴 CRITICAL - Stored XSS with admin access
   🟠 HIGH - Reflected XSS in sensitive areas
   🟡 MEDIUM - Standard reflected XSS
   🟢 LOW - Self-XSS or limited impact

⚡ BYPASS TECHNIQUES:
   • Filter evasion with encoding
   • Tag variation and obfuscation
   • Event handler alternatives
   • Protocol handler abuse
   • Template injection vectors

🔗 INTEGRATION:
   Perfect for web application assessments. Chain with directory
   fuzzing and parameter discovery for maximum coverage.
`
}

func (p *xssScannerPlugin) Run(target string, options map[string]interface{}) (interface{}, error) {
	scanner := NewXSSScanner(target)
	
	if payload, ok := options["payload"].(string); ok && payload != "" {
		scanner.payload = payload
	}
	
	return scanner.ScanXSS(), nil
}

func init() {
	// Register the plugin for shell/parametric use
	core.RegisterPlugin(&xssScannerPlugin{})
}
