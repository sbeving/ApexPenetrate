// internal/modules/reconnaissance/github_dork.go
package reconnaissance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"apexPenetrateGo/internal/core/logger"

	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
)

// GitHubDorkResult holds a single dork finding
type GitHubDorkResult struct {
	RepoName string
	FilePath string
	HTMLURL  string
	Snippet  string
}

// GitHubDorker holds state for dorking
type GitHubDorker struct {
	Target string
	Log    *logrus.Logger
	Token  string // Optional: GitHub API token for higher rate limits
}

// NewGitHubDorker creates a new dorker
func NewGitHubDorker(target, token string) *GitHubDorker {
	return &GitHubDorker{
		Target: target,
		Log:    logger.GetLogger(),
		Token:  token,
	}
}

// DorkQueries returns a list of dorks for the target
func (g *GitHubDorker) DorkQueries() []string {
	return []string{
		fmt.Sprintf("%s password", g.Target),
		fmt.Sprintf("%s api_key", g.Target),
		fmt.Sprintf("%s secret", g.Target),
		fmt.Sprintf("%s AWS_ACCESS_KEY_ID", g.Target),
		fmt.Sprintf("%s DB_PASSWORD", g.Target),
		fmt.Sprintf("%s filename:.env", g.Target),
		fmt.Sprintf("%s filename:config", g.Target),
		fmt.Sprintf("%s filename:credentials", g.Target),
	}
}

// Dork performs GitHub code search for leaks
func (g *GitHubDorker) Dork(ctx context.Context) ([]GitHubDorkResult, error) {
	g.Log.Infof("🤖 Starting GitHub dorking for %s...", g.Target)
	var results []GitHubDorkResult
	client := &http.Client{Timeout: 8 * time.Second}
	for _, dork := range g.DorkQueries() {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}
		q := url.QueryEscape(dork)
		apiURL := fmt.Sprintf("https://api.github.com/search/code?q=%s", q)
		req, _ := http.NewRequest("GET", apiURL, nil)
		req.Header.Set("Accept", "application/vnd.github.v3+json")
		if g.Token != "" {
			req.Header.Set("Authorization", "token "+g.Token)
		}
		resp, err := client.Do(req)
		if err != nil {
			g.Log.Warnf("GitHub API error: %v", err)
			continue
		}
		if resp.StatusCode == 403 {
			color.Red("❌ GitHub API rate limit hit. Set a GITHUB_TOKEN env var for more requests.")
			break
		}
		var apiResp struct {
			Items []struct {
				Repository struct {
					FullName string `json:"full_name"`
				} `json:"repository"`
				Path    string  `json:"path"`
				HTMLURL string  `json:"html_url"`
				Score   float64 `json:"score"`
			} `json:"items"`
		}
		json.NewDecoder(resp.Body).Decode(&apiResp)
		resp.Body.Close()
		for _, item := range apiResp.Items {
			results = append(results, GitHubDorkResult{
				RepoName: item.Repository.FullName,
				FilePath: item.Path,
				HTMLURL:  item.HTMLURL,
				Snippet:  fmt.Sprintf("Score: %.2f", item.Score),
			})
		}
		// Respect rate limits
		time.Sleep(2 * time.Second)
	}
	return results, nil
}

// PrintGitHubDorkResults prints dork results with color and emoji
func PrintGitHubDorkResults(results []GitHubDorkResult) {
	if len(results) == 0 {
		color.Yellow("⚠️  No GitHub leaks found.")
		return
	}
	color.Green("\n🕵️  GitHub Dorking Results:")
	for _, r := range results {
		color.Cyan("🔗 Repo: %s | File: %s", r.RepoName, r.FilePath)
		color.Magenta("    %s", r.HTMLURL)
		color.Yellow("    %s", r.Snippet)
	}
}
