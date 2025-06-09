// internal/modules/web_vulnerabilities/xss_scanner.go
package web_vulnerabilities

import (
	"apexPenetrateGo/internal/core/logger"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// XSSScanner holds the state for XSS scanning
type XSSScanner struct {
	url string
	log *logrus.Logger
}

// NewXSSScanner creates a new instance of XSSScanner
func NewXSSScanner(url string) *XSSScanner {
	return &XSSScanner{
		url: url,
		log: logger.GetLogger(),
	}
}

// ScanXSS performs a real reflected XSS test by injecting a payload and checking the response.
func (s *XSSScanner) ScanXSS() []map[string]string {
	s.log.Infof("Scanning for XSS in %s...", s.url)
	findings := []map[string]string{}
	testPayload := "<script>alert('xss')</script>"
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
