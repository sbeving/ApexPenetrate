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
func (p *xssScannerPlugin) Run(target string, options map[string]interface{}) (interface{}, error) {
	payload := "<script>alert('xss')</script>"
	if val, ok := options["payload"]; ok {
		if s, ok := val.(string); ok && s != "" {
			payload = s
		}
	}
	scanner := NewXSSScanner(target)
	scanner.payload = payload
	return scanner.ScanXSS(), nil
}

func init() {
	// Register the plugin for shell/parametric use
	core.RegisterPlugin(&xssScannerPlugin{})
}
