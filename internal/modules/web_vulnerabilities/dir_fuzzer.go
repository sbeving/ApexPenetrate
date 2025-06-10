// internal/modules/web_vulnerabilities/dir_fuzzer.go
package web_vulnerabilities

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"apexPenetrateGo/internal/core"
)

// DirFuzzerResult holds the results of directory/file fuzzing
type DirFuzzerResult struct {
	Target string
	Paths  []string
	Found  []string
}

// DirFuzzerConfig allows custom wordlists and settings
type DirFuzzerConfig struct {
	Wordlist []string
	Threads  int
	Timeout  time.Duration
}

// Default wordlist (can be extended)
var defaultDirs = []string{
	"admin", "login", "dashboard", "config", "backup", ".env", "robots.txt", ".git", "uploads", "api", "test", "old", "dev", "staging", "private", "db", "data", "tmp", "logs", "secret", "passwords.txt",
}

// DirFuzzer fuzzes for common files and directories
func DirFuzzer(target string, config *DirFuzzerConfig) *DirFuzzerResult {
	if !strings.HasPrefix(target, "http") {
		target = "http://" + target
	}
	wordlist := defaultDirs
	if config != nil && len(config.Wordlist) > 0 {
		wordlist = config.Wordlist
	}
	threads := 10
	if config != nil && config.Threads > 0 {
		threads = config.Threads
	}

	timeout := 3 * time.Second
	if config != nil && config.Timeout > 0 {
		timeout = config.Timeout
	}

	var found []string
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)
	client := &http.Client{Timeout: timeout}

	for _, path := range wordlist {
		wg.Add(1)
		sem <- struct{}{}
		go func(p string) {
			defer wg.Done()
			url := strings.TrimRight(target, "/") + "/" + p
			resp, err := client.Get(url)
			if err == nil && resp.StatusCode < 400 && resp.StatusCode >= 200 {
				found = append(found, url)
			}
			if resp != nil {
				resp.Body.Close()
			}
			<-sem
		}(path)
	}
	wg.Wait()
	return &DirFuzzerResult{Target: target, Paths: wordlist, Found: found}
}

func (r *DirFuzzerResult) String() string {
	if len(r.Found) == 0 {
		return fmt.Sprintf("No interesting files or directories found on %s.", r.Target)
	}
	return fmt.Sprintf("Found %d files/directories on %s:\n%s", len(r.Found), r.Target, strings.Join(r.Found, "\n"))
}

type dirFuzzerPlugin struct{}

func (p *dirFuzzerPlugin) Name() string { return "DirFuzzer" }
func (p *dirFuzzerPlugin) Description() string {
	return "Directory and file fuzzing with customizable wordlists"
}
func (p *dirFuzzerPlugin) Category() string { return "web-vuln" }
func (p *dirFuzzerPlugin) Options() []core.ModuleOption {
	return []core.ModuleOption{
		{Name: "wordlist", Type: "string", Default: "admin,login,dashboard,config,backup,.env,robots.txt,.git,uploads,api,test,old,dev,staging,private,db,data,tmp,logs,secret,passwords.txt", Description: "Comma-separated wordlist for fuzzing", Required: false},
		{Name: "threads", Type: "int", Default: 10, Description: "Number of concurrent threads", Required: false},
		{Name: "timeout", Type: "string", Default: "3s", Description: "Timeout per request", Required: false},
	}
}
func (p *dirFuzzerPlugin) Run(target string, options map[string]interface{}) (interface{}, error) {
	config := &DirFuzzerConfig{}

	// Parse wordlist
	if wordlistStr, ok := options["wordlist"].(string); ok && wordlistStr != "" {
		config.Wordlist = strings.Split(wordlistStr, ",")
		for i := range config.Wordlist {
			config.Wordlist[i] = strings.TrimSpace(config.Wordlist[i])
		}
	}

	// Parse threads
	if threads, ok := options["threads"].(int); ok {
		config.Threads = threads
	}

	// Parse timeout
	if timeoutStr, ok := options["timeout"].(string); ok {
		if timeout, err := time.ParseDuration(timeoutStr); err == nil {
			config.Timeout = timeout
		}
	}

	return DirFuzzer(target, config), nil
}

func (p *dirFuzzerPlugin) Help() string {
	return `
📁 Directory Fuzzer - Hidden Directory & File Discovery Tool

DESCRIPTION:
  Discovers hidden directories and files by fuzzing common paths and filenames.
  Essential for finding admin panels, backup files, and sensitive directories.

USAGE:
  dirfuzzer <target_url> [options]

OPTIONS:
  wordlist  - Comma-separated list of directories/files to test
  threads   - Number of concurrent requests (default: 10)
  timeout   - Request timeout (e.g., "5s", "10s")

EXAMPLES:
  dirfuzzer https://example.com
  dirfuzzer https://example.com --wordlist admin,backup,test
  dirfuzzer https://example.com --threads 20 --timeout 5s

COMMON TARGETS:
  • Admin Panels: admin, administrator, panel, control
  • Backup Files: backup, old, bak, temp, archive
  • Config Files: config, conf, settings, env
  • Development: dev, test, staging, debug
  • Documentation: docs, documentation, help, manual

ATTACK SCENARIOS:
  • Admin Interface Discovery: Find hidden admin panels
  • Backup File Access: Locate exposed backup files with credentials
  • Source Code Leaks: Discover development/staging environments
  • Configuration Exposure: Find config files with sensitive data

EVASION TECHNIQUES:
  • Use random User-Agent headers
  • Implement request delays to avoid rate limiting
  • Try different HTTP methods (GET, POST, HEAD)
  • Test with various file extensions (.php, .asp, .jsp)

PRO TIPS:
  💡 Check response sizes - small differences may indicate valid paths
  💡 Look for different HTTP status codes (403 vs 404)
  💡 Test common CMS paths (/wp-admin, /admin, /administrator)
  💡 Try file extensions based on detected technology stack
  💡 Use wordlists specific to discovered technologies
  💡 Check for directory listing vulnerabilities (200 with index content)

WORDLIST RECOMMENDATIONS:
  • SecLists: Common-Web-Content-Discovery
  • DirBuster wordlists
  • Custom wordlists based on target technology

RISK LEVEL: Medium to High (sensitive data exposure)
`
}

func init() {
	core.RegisterPlugin(&dirFuzzerPlugin{})
}
