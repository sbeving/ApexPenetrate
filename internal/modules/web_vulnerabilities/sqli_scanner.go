package web_vulnerabilities

import (
	"io"
	"net/http"
	"strings"
)

type SQLiScanner struct {
	URL string
}

func NewSQLiScanner(url string) *SQLiScanner {
	return &SQLiScanner{URL: url}
}

func (s *SQLiScanner) ScanSQLi() []map[string]string {
	findings := []map[string]string{}
	payloads := []string{"' OR '1'='1", "'--", "' OR 1=1--"}
	for _, payload := range payloads {
		testURL := s.URL
		if strings.Contains(testURL, "?") {
			testURL += "&id=" + payload
		} else {
			testURL += "?id=" + payload
		}
		resp, err := http.Get(testURL)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if strings.Contains(strings.ToLower(string(body)), "sql syntax") || strings.Contains(strings.ToLower(string(body)), "mysql") {
			findings = append(findings, map[string]string{
				"url":      testURL,
				"payload":  payload,
				"evidence": "SQL error in response",
			})
		}
	}
	return findings
}
