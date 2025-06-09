// internal/modules/reconnaissance/subdomain_enum.go
package reconnaissance

import (
	"apexPenetrateGo/internal/core/logger"
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	defaultWordlistSize = 100 // A small default for demo, real tools use much larger
	concurrencyLimit    = 50  // Limit concurrent goroutines for HTTP requests
	httpTimeout         = 3 * time.Second
)

var defaultWordlist = []string{
	"www", "mail", "dev", "test", "api", "blog", "admin", "ftp", "webmail", "ns1", "ns2",
	"stage", "staging", "beta", "shop", "store", "portal", "vpn", "docs", "jira", "wiki",
	"cpanel", "autodiscover", "m", "mobile", "app", "cdn", "status", "secure", "proxy",
	"sso", "id", "login", "register", "forum", "community", "support", "dashboard",
	"files", "downloads", "media", "data", "images", "videos", "assets", "static",
	"partner", "client", "customer", "extranet", "intranet", "help", "kb", "news",
	"payments", "checkout", "careers", "jobs", "hr", "corp", "enterprise", "cloud",
	"service", "backend", "frontend", "prod", "uat", "qa", "demo", "lab", "poc",
	"vps", "server", "cluster", "node", "gateway", "router", "firewall", "monitor",
	"alert", "backup", "restore", "mirror", "repo", "git", "svn", "test1", "test2",
	"test3", "dev1", "dev2", "dev3", "old", "new", "archive", "legacy", "v1", "v2",
}

// Global HTTP client to be mocked in tests
var DefaultHTTPClient = &http.Client{
	Timeout: httpTimeout,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// SubdomainEnumerator holds the state for subdomain enumeration
type SubdomainEnumerator struct {
	target          string
	wordlistPath    string
	foundSubdomains chan string // Channel to send found subdomains
	wg              sync.WaitGroup
	httpClient      *http.Client
	log             *logrus.Logger
}

// NewSubdomainEnumerator creates a new instance of SubdomainEnumerator
func NewSubdomainEnumerator(target string, wordlistPath string) *SubdomainEnumerator {
	// Clean target from scheme and paths
	cleanedTarget := strings.TrimPrefix(target, "http://")
	cleanedTarget = strings.TrimPrefix(cleanedTarget, "https://")
	cleanedTarget = strings.Split(cleanedTarget, "/")[0]

	return &SubdomainEnumerator{
		target:          cleanedTarget,
		wordlistPath:    wordlistPath,
		foundSubdomains: make(chan string),
		httpClient:      DefaultHTTPClient, // Use the global client
		log:             logger.GetLogger(),
	}
}

// EnumerateSubdomains performs subdomain enumeration
func (s *SubdomainEnumerator) EnumerateSubdomains() ([]string, error) {
	s.log.Infof("Starting subdomain enumeration for %s...", s.target)

	wordlist, err := s.loadWordlist()
	if err != nil {
		return nil, fmt.Errorf("failed to load wordlist: %w", err)
	}

	// Channel to limit concurrency
	guard := make(chan struct{}, concurrencyLimit)
	var mu sync.Mutex // Mutex to protect foundSubdomainsSlice
	foundSubdomainsSlice := []string{}

	// Start a goroutine to collect results from the channel
	go func() {
		for sub := range s.foundSubdomains {
			mu.Lock()
			foundSubdomainsSlice = append(foundSubdomainsSlice, sub)
			mu.Unlock()
		}
	}()

	// Brute-force enumeration
	s.log.Infof("Starting brute-force enumeration with %d workers...", concurrencyLimit)
	for _, sub := range wordlist {
		s.wg.Add(1)
		guard <- struct{}{} // Acquire a slot
		go func(sub string) {
			defer s.wg.Done()
			defer func() { <-guard }() // Release the slot

			fullDomain := fmt.Sprintf("%s.%s", sub, s.target)
			if s.resolveSubdomain(fullDomain) {
				s.foundSubdomains <- fullDomain
			}
		}(sub)
	}

	// Placeholder for passive enumeration sources
	s.passiveEnumPlaceholder()

	s.wg.Wait()              // Wait for all active goroutines to finish
	close(s.foundSubdomains) // Close the channel when all producers are done

	// Sort and return unique subdomains
	uniqueSubdomains := make(map[string]struct{})
	for _, sub := range foundSubdomainsSlice {
		uniqueSubdomains[sub] = struct{}{}
	}

	var results []string
	for sub := range uniqueSubdomains {
		results = append(results, sub)
	}
	s.log.Infof("Finished subdomain enumeration for %s. Found %d subdomains.", s.target, len(results))
	return results, nil
}

// loadWordlist loads the wordlist from a file or uses a default one.
func (s *SubdomainEnumerator) loadWordlist() ([]string, error) {
	if s.wordlistPath != "" {
		file, err := os.Open(s.wordlistPath)
		if err != nil {
			s.log.Warnf("Custom wordlist not found at %s. Falling back to default.", s.wordlistPath)
			return defaultWordlist, nil // Fallback to default if file not found
		}
		defer file.Close()

		var words []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			word := strings.TrimSpace(scanner.Text())
			if word != "" {
				words = append(words, word)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error reading wordlist file: %w", err)
		}
		s.log.Infof("Using custom wordlist from %s (%d entries).", s.wordlistPath, len(words))
		return words, nil
	}
	s.log.Infof("Using default wordlist (%d entries).", len(defaultWordlist))
	return defaultWordlist, nil
}

// resolveSubdomain attempts to resolve a subdomain via HTTP HEAD request.
func (s *SubdomainEnumerator) resolveSubdomain(fullDomain string) bool {
	// Try both HTTP and HTTPS
	urls := []string{fmt.Sprintf("https://%s", fullDomain), fmt.Sprintf("http://%s", fullDomain)}

	for _, url := range urls {
		req, err := http.NewRequest("HEAD", url, nil)
		if err != nil {
			s.log.Debugf("Error creating request for %s: %v", url, err)
			continue
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			// Check for specific network errors
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.log.Debugf("Timeout for %s: %v", url, err)
				continue
			}
			s.log.Debugf("Request error for %s: %v", url, err)
			continue
		}
		defer resp.Body.Close()

		// Any 2xx or 3xx status code indicates it resolved and is accessible
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			s.log.Debugf("Resolved: %s (Status: %d)", url, resp.StatusCode)
			return true
		}
	}
	return false
}

// passiveEnumPlaceholder simulates finding subdomains from passive sources.
func (s *SubdomainEnumerator) passiveEnumPlaceholder() {
	s.log.Info("Performing passive enumeration (placeholder)...")
	// In a real tool, you would integrate with external APIs or services
	// e.g., using a library for ProjectDiscovery's Subfinder, Recon.dev, etc.
	if s.target == "example.com" {
		s.foundSubdomains <- "test.example.com"
		s.foundSubdomains <- "another.example.com"
		s.wg.Add(2) // Account for these "found" subdomains in the WaitGroup
		go func() { defer s.wg.Done(); s.log.Debugf("Passive found: test.example.com") }()
		go func() { defer s.wg.Done(); s.log.Debugf("Passive found: another.example.com") }()
	}
	// Add a small delay to simulate network calls
	time.Sleep(500 * time.Millisecond)
}

// GetDefaultWordlist is exposed for testing purposes
func GetDefaultWordlist() []string {
	return defaultWordlist
}
