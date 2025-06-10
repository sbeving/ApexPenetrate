// internal/modules/web_vulnerabilities/cors_tester.go
package web_vulnerabilities

import (
	"apexPenetrateGo/internal/core"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type CORSResult struct {
	Target     string
	OriginTest string
	Headers    map[string]string
	Findings   []string
}

func CORSTester(target string) *CORSResult {
	if !strings.HasPrefix(target, "http") {
		target = "http://" + target
	}
	originTest := "https://evil.com"
	client := &http.Client{Timeout: 6 * time.Second}
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return &CORSResult{Target: target, Findings: []string{"❌ Request error: " + err.Error()}}
	}
	req.Header.Set("Origin", originTest)
	resp, err := client.Do(req)
	if err != nil {
		return &CORSResult{Target: target, Findings: []string{"❌ HTTP error: " + err.Error()}}
	}
	defer resp.Body.Close()
	findings := []string{}
	headers := map[string]string{}
	for k, v := range resp.Header {
		headers[k] = strings.Join(v, ", ")
	}
	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	allowCreds := resp.Header.Get("Access-Control-Allow-Credentials")
	if allowOrigin == "*" {
		findings = append(findings, "⚠️ Access-Control-Allow-Origin is wildcard (*) — permissive!")
	}
	if allowOrigin == originTest {
		findings = append(findings, "⚠️ Access-Control-Allow-Origin reflects Origin header — vulnerable to reflection!")
	}
	if allowCreds == "true" && (allowOrigin == "*" || allowOrigin == originTest) {
		findings = append(findings, "🚨 Credentials allowed with permissive origin — critical misconfiguration!")
	}
	if allowOrigin == "" {
		findings = append(findings, "✅ No CORS headers detected (default safe)")
	}
	if len(findings) == 0 {
		findings = append(findings, "✅ No obvious CORS misconfigurations detected.")
	}
	return &CORSResult{
		Target:     target,
		OriginTest: originTest,
		Headers:    headers,
		Findings:   findings,
	}
}

func (r *CORSResult) String() string {
	msg := fmt.Sprintf("\n🛡️  CORS Tester for %s (Origin: %s):\n", r.Target, r.OriginTest)
	for _, f := range r.Findings {
		msg += "  " + f + "\n"
	}
	if len(r.Headers) > 0 {
		msg += "  Response Headers:\n"
		for k, v := range r.Headers {
			if strings.HasPrefix(strings.ToLower(k), "access-control-") {
				msg += fmt.Sprintf("    %s: %s\n", k, v)
			}
		}
	}
	return msg
}

type corsTesterPlugin struct{}

func (p *corsTesterPlugin) Name() string { return "CORSTester" }
func (p *corsTesterPlugin) Description() string {
	return "Detects CORS misconfigurations (wildcard, reflection, credentials)"
}
func (p *corsTesterPlugin) Run(target string, options map[string]interface{}) (interface{}, error) {
	return CORSTester(target), nil
}
func (p *corsTesterPlugin) Category() string { return "web" }
func (p *corsTesterPlugin) Options() []core.ModuleOption {
	return []core.ModuleOption{
		{Name: "origin", Type: "string", Default: "https://evil.com", Description: "Origin header to test for CORS", Required: false},
	}
}

func init() {
	core.RegisterPlugin(&corsTesterPlugin{})
}
