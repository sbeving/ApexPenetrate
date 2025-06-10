// internal/modules/reconnaissance/cve_scanner.go
package reconnaissance

import (
	"apexPenetrateGo/internal/core"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type CVEResult struct {
	ID          string   `json:"id"`
	Summary     string   `json:"summary"`
	CVSS        float64  `json:"cvss"`
	Severity    string   `json:"severity"`
	PublishedAt string   `json:"published"`
	References  []string `json:"references"`
}

type CVEScannerResult struct {
	Target     string
	Service    string
	Version    string
	CVEs       []CVEResult
	TotalFound int
	HighRisk   int
	MediumRisk int
	LowRisk    int
}

// CVEScanner scans for known CVEs based on service and version
func CVEScanner(service, version string) *CVEScannerResult {
	result := &CVEScannerResult{
		Service: service,
		Version: version,
		CVEs:    []CVEResult{},
	}

	// Try multiple CVE data sources
	cves := []CVEResult{}

	// 1. Try CVE.circl.lu API (free, no auth required)
	circlCVEs, err := searchCirclCVE(service, version)
	if err == nil {
		cves = append(cves, circlCVEs...)
	}

	// 2. Try NVD-like search (mock for now, would need real API)
	nvdCVEs := searchMockNVD(service, version)
	cves = append(cves, nvdCVEs...)

	// Count by severity
	high, medium, low := 0, 0, 0
	for _, cve := range cves {
		switch cve.Severity {
		case "HIGH", "CRITICAL":
			high++
		case "MEDIUM":
			medium++
		case "LOW":
			low++
		}
	}

	result.CVEs = cves
	result.TotalFound = len(cves)
	result.HighRisk = high
	result.MediumRisk = medium
	result.LowRisk = low

	return result
}

func searchCirclCVE(service, version string) ([]CVEResult, error) {
	// CVE.circl.lu API search
	query := fmt.Sprintf("%s %s", service, version)
	encodedQuery := url.QueryEscape(query)
	apiURL := fmt.Sprintf("https://cve.circl.lu/api/search/%s", encodedQuery)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("CVE API returned status %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse the response (format depends on actual API)
	var apiResponse map[string]interface{}
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		return nil, err
	}

	// Convert to our CVEResult format (simplified)
	cves := []CVEResult{}
	if results, ok := apiResponse["results"].([]interface{}); ok {
		for _, result := range results {
			if cveData, ok := result.(map[string]interface{}); ok {
				cve := CVEResult{
					ID:      getString(cveData, "id"),
					Summary: getString(cveData, "summary"),
					CVSS:    getFloat(cveData, "cvss"),
				}

				// Determine severity based on CVSS
				if cve.CVSS >= 7.0 {
					cve.Severity = "HIGH"
				} else if cve.CVSS >= 4.0 {
					cve.Severity = "MEDIUM"
				} else {
					cve.Severity = "LOW"
				}

				cves = append(cves, cve)
			}
		}
	}

	return cves, nil
}

func searchMockNVD(service, version string) []CVEResult {
	// Mock CVE data for common services (in real implementation, use NVD API)
	mockCVEs := map[string][]CVEResult{
		"apache": {
			{ID: "CVE-2021-44228", Summary: "Log4j Remote Code Execution", CVSS: 10.0, Severity: "CRITICAL", PublishedAt: "2021-12-10"},
			{ID: "CVE-2021-45046", Summary: "Log4j DoS vulnerability", CVSS: 3.7, Severity: "LOW", PublishedAt: "2021-12-14"},
		},
		"nginx": {
			{ID: "CVE-2021-23017", Summary: "nginx DNS resolver vulnerability", CVSS: 6.4, Severity: "MEDIUM", PublishedAt: "2021-05-25"},
		},
		"openssh": {
			{ID: "CVE-2020-14145", Summary: "OpenSSH observable discrepancy", CVSS: 5.9, Severity: "MEDIUM", PublishedAt: "2020-06-17"},
		},
		"mysql": {
			{ID: "CVE-2021-2194", Summary: "MySQL Server vulnerability", CVSS: 4.9, Severity: "MEDIUM", PublishedAt: "2021-04-20"},
		},
	}

	service = strings.ToLower(service)
	for mockService, cves := range mockCVEs {
		if strings.Contains(service, mockService) {
			return cves
		}
	}

	return []CVEResult{}
}

func getString(data map[string]interface{}, key string) string {
	if val, ok := data[key].(string); ok {
		return val
	}
	return ""
}

func getFloat(data map[string]interface{}, key string) float64 {
	if val, ok := data[key].(float64); ok {
		return val
	}
	return 0.0
}

func (r *CVEScannerResult) String() string {
	msg := fmt.Sprintf("\n🔍 CVE Scanner Results for %s %s:\n", r.Service, r.Version)
	msg += fmt.Sprintf("📊 Total CVEs: %d (🔴 High: %d, 🟡 Medium: %d, 🟢 Low: %d)\n\n",
		r.TotalFound, r.HighRisk, r.MediumRisk, r.LowRisk)

	if len(r.CVEs) == 0 {
		msg += "✅ No known CVEs found for this service/version.\n"
		return msg
	}

	for _, cve := range r.CVEs {
		severity_emoji := "🟢"
		if cve.Severity == "HIGH" || cve.Severity == "CRITICAL" {
			severity_emoji = "🔴"
		} else if cve.Severity == "MEDIUM" {
			severity_emoji = "🟡"
		}

		msg += fmt.Sprintf("%s %s (CVSS: %.1f) - %s\n", severity_emoji, cve.ID, cve.CVSS, cve.Severity)
		if cve.Summary != "" {
			msg += fmt.Sprintf("   📝 %s\n", cve.Summary)
		}
		if cve.PublishedAt != "" {
			msg += fmt.Sprintf("   📅 Published: %s\n", cve.PublishedAt)
		}
		msg += "\n"
	}

	return msg
}

type cveScannerPlugin struct{}

func (p *cveScannerPlugin) Name() string { return "CVEScanner" }
func (p *cveScannerPlugin) Description() string {
	return "Scans for known CVEs based on service and version"
}
func (p *cveScannerPlugin) Category() string { return "vuln" }
func (p *cveScannerPlugin) Options() []core.ModuleOption {
	return []core.ModuleOption{
		{Name: "service", Type: "string", Default: "", Description: "Service name (e.g., apache, nginx, openssh)", Required: true},
		{Name: "version", Type: "string", Default: "", Description: "Service version (e.g., 2.4.41, 1.18.0)", Required: true},
	}
}
func (p *cveScannerPlugin) Run(target string, options map[string]interface{}) (interface{}, error) {
	service := ""
	version := ""

	if val, ok := options["service"]; ok {
		if s, ok := val.(string); ok {
			service = s
		}
	}
	if val, ok := options["version"]; ok {
		if s, ok := val.(string); ok {
			version = s
		}
	}

	if service == "" || version == "" {
		return nil, fmt.Errorf("both service and version are required")
	}

	result := CVEScanner(service, version)
	result.Target = target
	return result, nil
}

func init() {
	core.RegisterPlugin(&cveScannerPlugin{})
}
