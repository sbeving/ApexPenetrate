// internal/modules/web_vulnerabilities/open_redirect.go
package web_vulnerabilities

import (
	"apexPenetrateGo/internal/core"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type OpenRedirectResult struct {
	Target          string
	Vulnerable      bool
	TestedParams    []string
	Vulnerabilities []OpenRedirectVuln
	Note            string
}

type OpenRedirectVuln struct {
	Parameter string
	Payload   string
	URL       string
	Status    int
	Location  string
}

// Common redirect parameters and payloads
var redirectParams = []string{
	"redirect", "url", "link", "goto", "target", "rurl", "dest",
	"destination", "redir", "redirect_url", "redirect_uri", "return",
	"returnTo", "return_to", "checkout_url", "continue", "return_path",
}

var redirectPayloads = []string{
	"//evil.com",
	"https://evil.com",
	"//evil.com/",
	"https://evil.com/",
	"javascript:alert('xss')",
	"\\\\evil.com",
	"//evil.com%2f",
	"//evil.com%2F",
	"//evil.com%E3%80%82",
	"/\\evil.com",
	"htTp://evil.com",
	"htTps://evil.com",
}

func OpenRedirectScan(target string, customParams []string, customPayloads []string) *OpenRedirectResult {
	if !strings.HasPrefix(target, "http") {
		target = "http://" + target
	}

	params := redirectParams
	if len(customParams) > 0 {
		params = append(params, customParams...)
	}

	payloads := redirectPayloads
	if len(customPayloads) > 0 {
		payloads = append(payloads, customPayloads...)
	}

	result := &OpenRedirectResult{
		Target:          target,
		TestedParams:    params,
		Vulnerabilities: []OpenRedirectVuln{},
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects, we want to check them manually
			return http.ErrUseLastResponse
		},
	}

	for _, param := range params {
		for _, payload := range payloads {
			testURL := buildTestURL(target, param, payload)

			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			// Check for redirect responses
			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				location := resp.Header.Get("Location")
				if location != "" && isVulnerable(location, payload) {
					result.Vulnerabilities = append(result.Vulnerabilities, OpenRedirectVuln{
						Parameter: param,
						Payload:   payload,
						URL:       testURL,
						Status:    resp.StatusCode,
						Location:  location,
					})
					result.Vulnerable = true
				}
			}
		}
	}

	if result.Vulnerable {
		result.Note = fmt.Sprintf("Found %d open redirect vulnerabilities", len(result.Vulnerabilities))
	} else {
		result.Note = "No open redirect vulnerabilities detected"
	}

	return result
}

func buildTestURL(baseURL, param, payload string) string {
	if strings.Contains(baseURL, "?") {
		return fmt.Sprintf("%s&%s=%s", baseURL, param, url.QueryEscape(payload))
	}
	return fmt.Sprintf("%s?%s=%s", baseURL, param, url.QueryEscape(payload))
}

func isVulnerable(location, payload string) bool {
	// Check if the location header contains our payload or redirects to external domain
	location = strings.ToLower(location)
	payload = strings.ToLower(payload)

	// Direct payload match
	if strings.Contains(location, "evil.com") {
		return true
	}

	// JavaScript payload
	if strings.Contains(location, "javascript:") {
		return true
	}

	// Protocol-relative URLs to external domains
	if strings.HasPrefix(location, "//") && strings.Contains(location, "evil.com") {
		return true
	}

	return false
}

func (r *OpenRedirectResult) String() string {
	status := "🔒"
	if r.Vulnerable {
		status = "🚨"
	}

	msg := fmt.Sprintf("\n%s Open Redirect Scanner for %s:\n", status, r.Target)
	msg += fmt.Sprintf("  Tested %d parameters with %d payloads\n", len(r.TestedParams), len(redirectPayloads))

	if r.Vulnerable {
		msg += fmt.Sprintf("  🚨 VULNERABLE: Found %d open redirect issues:\n", len(r.Vulnerabilities))
		for i, vuln := range r.Vulnerabilities {
			msg += fmt.Sprintf("    %d. Parameter: %s\n", i+1, vuln.Parameter)
			msg += fmt.Sprintf("       Payload: %s\n", vuln.Payload)
			msg += fmt.Sprintf("       Status: %d\n", vuln.Status)
			msg += fmt.Sprintf("       Location: %s\n", vuln.Location)
			msg += fmt.Sprintf("       Test URL: %s\n", vuln.URL)
		}
	} else {
		msg += "  ✅ No open redirect vulnerabilities found\n"
	}

	msg += fmt.Sprintf("  Note: %s\n", r.Note)
	return msg
}

type openRedirectPlugin struct{}

func (p *openRedirectPlugin) Name() string { return "OpenRedirect" }
func (p *openRedirectPlugin) Description() string {
	return "Scans for open redirect vulnerabilities with various payloads"
}
func (p *openRedirectPlugin) Category() string { return "web-vuln" }
func (p *openRedirectPlugin) Options() []core.ModuleOption {
	return []core.ModuleOption{
		{Name: "params", Type: "string", Default: "", Description: "Comma-separated custom redirect parameters", Required: false},
		{Name: "payloads", Type: "string", Default: "", Description: "Comma-separated custom payloads", Required: false},
		{Name: "timeout", Type: "string", Default: "10s", Description: "HTTP request timeout", Required: false},
	}
}
func (p *openRedirectPlugin) Run(target string, options map[string]interface{}) (interface{}, error) {
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

	return OpenRedirectScan(target, customParams, customPayloads), nil
}

func init() {
	core.RegisterPlugin(&openRedirectPlugin{})
}
