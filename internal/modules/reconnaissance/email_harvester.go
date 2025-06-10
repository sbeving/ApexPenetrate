// internal/modules/reconnaissance/email_harvester.go
package reconnaissance

import (
	"apexPenetrateGo/internal/core"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type EmailHarvesterResult struct {
	Domain string
	Emails []string
	Source string
	Note   string
}

func EmailHarvester(domain string) *EmailHarvesterResult {
	apiKey := os.Getenv("HUNTERIO_API_KEY")
	if apiKey != "" {
		return hunterioHarvest(domain, apiKey)
	}
	// Fallback: suggest Google/LinkedIn dorks
	dorks := []string{
		fmt.Sprintf("site:linkedin.com/in @%s", domain),
		fmt.Sprintf("site:linkedin.com/company @%s", domain),
		fmt.Sprintf("site:twitter.com @%s", domain),
		fmt.Sprintf("site:facebook.com @%s", domain),
		fmt.Sprintf("site:%s email", domain),
	}
	return &EmailHarvesterResult{
		Domain: domain,
		Emails: dorks,
		Source: "dork",
		Note:   "No Hunter.io API key set. Use these dorks in Google/Bing for manual discovery.",
	}
}

func hunterioHarvest(domain, apiKey string) *EmailHarvesterResult {
	url := fmt.Sprintf("https://api.hunter.io/v2/domain-search?domain=%s&api_key=%s", domain, apiKey)
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return &EmailHarvesterResult{Domain: domain, Source: "hunter.io", Note: "API error: " + err.Error()}
	}
	defer resp.Body.Close()
	var data struct {
		Data struct {
			Emails []struct {
				Value string `json:"value"`
			} `json:"emails"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return &EmailHarvesterResult{Domain: domain, Source: "hunter.io", Note: "JSON decode error"}
	}
	emails := []string{}
	for _, e := range data.Data.Emails {
		emails = append(emails, e.Value)
	}
	return &EmailHarvesterResult{
		Domain: domain,
		Emails: emails,
		Source: "hunter.io",
		Note:   fmt.Sprintf("%d emails found", len(emails)),
	}
}

func (r *EmailHarvesterResult) String() string {
	if len(r.Emails) == 0 {
		return fmt.Sprintf("\n📧 Email Harvester for %s: No emails found. %s", r.Domain, r.Note)
	}
	return fmt.Sprintf("\n📧 Email Harvester for %s (source: %s):\n  %s\n  Note: %s\n", r.Domain, r.Source, strings.Join(r.Emails, ", "), r.Note)
}

type emailHarvesterPlugin struct{}

func (p *emailHarvesterPlugin) Name() string { return "EmailHarvester" }
func (p *emailHarvesterPlugin) Description() string {
	return "Harvests emails using Hunter.io or dorking patterns"
}
func (p *emailHarvesterPlugin) Run(target string, options map[string]interface{}) (interface{}, error) {
	return EmailHarvester(target), nil
}
func (p *emailHarvesterPlugin) Category() string { return "recon" }
func (p *emailHarvesterPlugin) Options() []core.ModuleOption {
	return []core.ModuleOption{
		{Name: "api_key", Type: "string", Default: "", Description: "Hunter.io API key (optional)", Required: false},
		{Name: "use_dorks", Type: "bool", Default: true, Description: "Include Google/Bing dorks if no API key", Required: false},
	}
}

func init() {
	core.RegisterPlugin(&emailHarvesterPlugin{})
}
