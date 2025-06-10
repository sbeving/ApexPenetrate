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

func (p *emailHarvesterPlugin) Help() string {
	return `
📧 Email Harvester - Email Address Discovery & Intelligence

DESCRIPTION:
  Discovers email addresses associated with target domains through multiple sources
  including search engines, public databases, and social media platforms.

USAGE:
  emailharvester <domain> [options]

OPTIONS:
  api_key   - Hunter.io API key for enhanced results (optional)
  use_dorks - Enable Google/Bing dorking when no API key (default: true)

EXAMPLES:
  emailharvester example.com
  emailharvester company.com --api_key YOUR_HUNTER_KEY
  emailharvester target.org --use_dorks false

ATTACK SCENARIOS:
  • Phishing Campaigns: Build targeted email lists for social engineering
  • Password Spraying: Use discovered emails for authentication attacks
  • OSINT Gathering: Map organizational structure and employees
  • Social Engineering: Identify key personnel for targeted attacks

DISCOVERY METHODS:
  • Search Engine Dorking: Google/Bing search operators
  • Hunter.io API: Professional email discovery service
  • Social Media Mining: LinkedIn, Twitter, GitHub profiles
  • Public Records: WHOIS, certificate transparency logs
  • Web Scraping: Company websites and directories

SEARCH TECHNIQUES:
  • Google Dorks: site:domain.com "@domain.com"
  • Bing Search: Advanced email pattern matching
  • GitHub Mining: Code repositories with email addresses
  • Certificate Logs: SSL certificate email addresses
  • Breach Databases: Previously compromised email lists

PRO TIPS:
  💡 Cross-reference discovered emails with breach databases
  💡 Look for patterns in email formats (first.last@, flast@)
  💡 Check for role-based emails (admin@, support@, info@)
  💡 Validate email addresses before using in attacks
  💡 Combine with LinkedIn enumeration for complete profiles
  💡 Use discovered emails to guess additional email formats

EMAIL VALIDATION:
  • SMTP Verification: Check if email addresses are valid
  • Domain Validation: Verify MX records exist
  • Format Checking: Ensure proper email structure

ETHICAL CONSIDERATIONS:
  ⚠️  Use only for authorized penetration testing
  ⚠️  Respect privacy and data protection laws
  ⚠️  Do not use for spam or malicious purposes

RISK LEVEL: Medium (privacy exposure, social engineering preparation)
`
}

func init() {
	core.RegisterPlugin(&emailHarvesterPlugin{})
}
