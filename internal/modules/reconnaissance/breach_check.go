// internal/modules/reconnaissance/breach_check.go
package reconnaissance

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/fatih/color"
)

type BreachResult struct {
	Source  string
	Found   bool
	Details string
}

// HaveIBeenPwnedCheck checks for breaches using the public unifiedsearch endpoint (no API key required)
func HaveIBeenPwnedCheck(email string) (*BreachResult, error) {
	url := fmt.Sprintf("https://haveibeenpwned.com/unifiedsearch/%s", email)
	client := &http.Client{Timeout: 8 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "ApexPenetrateGo")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return &BreachResult{Source: "HaveIBeenPwned", Found: false, Details: "No breach found."}, nil
	}
	if resp.StatusCode != 200 {
		return &BreachResult{Source: "HaveIBeenPwned", Found: false, Details: fmt.Sprintf("Unexpected status: %d", resp.StatusCode)}, nil
	}
	body, _ := ioutil.ReadAll(resp.Body)
	var data map[string]interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return &BreachResult{Source: "HaveIBeenPwned", Found: false, Details: "Failed to parse response."}, nil
	}
	breaches, ok := data["Breaches"].([]interface{})
	if !ok || len(breaches) == 0 {
		return &BreachResult{Source: "HaveIBeenPwned", Found: false, Details: "No breach found."}, nil
	}
	var names []string
	for _, b := range breaches {
		if breachMap, ok := b.(map[string]interface{}); ok {
			if name, ok := breachMap["Name"].(string); ok {
				names = append(names, name)
			}
		}
	}
	if len(names) == 0 {
		return &BreachResult{Source: "HaveIBeenPwned", Found: false, Details: "No breach found."}, nil
	}
	return &BreachResult{Source: "HaveIBeenPwned", Found: true, Details: "Breached in: " + strings.Join(names, ", ")}, nil
}

// PrintBreachResults prints breach check results with color and emoji
func PrintBreachResults(results []*BreachResult) {
	for _, r := range results {
		if r.Found {
			color.Red("\n🛑 %s: %s", r.Source, r.Details)
		} else {
			color.Green("\n✅ %s: %s", r.Source, r.Details)
		}
	}
}

// TODO: Add Dehashed and Pastebin checks (requires API keys)
// func DehashedCheck(query string) (*BreachResult, error) { ... }
// func PastebinCheck(query string) (*BreachResult, error) { ... }
