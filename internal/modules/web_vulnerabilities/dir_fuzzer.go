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

func init() {
	core.RegisterPlugin(&dirFuzzerPlugin{})
}
