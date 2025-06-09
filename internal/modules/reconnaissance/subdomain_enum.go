// internal/modules/reconnaissance/subdomain_enum.go
package reconnaissance

import (
	"apexPenetrateGo/internal/core/logger"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	concurrencyLimit = 30
	httpTimeout      = 3 * time.Second
)

var DefaultHTTPClient = &http.Client{
	Timeout: httpTimeout,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// SubdomainEnumerator holds the state for subdomain enumeration
type SubdomainEnumerator struct {
	Target          string // Exported for testing
	foundSubdomains chan string // Channel to send found subdomains
	wg              sync.WaitGroup
	httpClient      *http.Client
	log             *logrus.Logger
}

// NewSubdomainEnumerator creates a new instance of SubdomainEnumerator
func NewSubdomainEnumerator(target string) *SubdomainEnumerator {
	cleanedTarget := strings.TrimPrefix(target, "http://")
	cleanedTarget = strings.TrimPrefix(cleanedTarget, "https://")
	cleanedTarget = strings.Split(cleanedTarget, "/")[0]
	return &SubdomainEnumerator{
		Target:          cleanedTarget,
		foundSubdomains: make(chan string),
		httpClient:      DefaultHTTPClient,
		log:             logger.GetLogger(),
	}
}

// EnumerateSubdomains performs subdomain enumeration
func (s *SubdomainEnumerator) EnumerateSubdomains() ([]string, error) {
	s.log.Infof("🔎 Starting advanced subdomain enumeration for %s...", s.Target)

	var allSubs []string
	var mu sync.Mutex

	// Start collector goroutine
	go func() {
		for sub := range s.foundSubdomains {
			mu.Lock()
			allSubs = append(allSubs, sub)
			mu.Unlock()
		}
	}()

	// DNS methods
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.dnsRecordsEnum()
	}()

	// OSINT: crt.sh
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.crtshEnum()
	}()

	s.wg.Wait()
	close(s.foundSubdomains)

	// Deduplicate and validate
	unique := make(map[string]struct{})
	var working []string
	for _, sub := range allSubs {
		sub = strings.ToLower(sub)
		if _, ok := unique[sub]; ok {
			continue
		}
		unique[sub] = struct{}{}
		if s.isAlive(sub) {
			working = append(working, sub)
		}
	}

	s.log.Infof("✅ Finished subdomain enumeration for %s. Found %d working subdomains.", s.Target, len(working))
	return working, nil
}

// dnsRecordsEnum finds subdomains via DNS records (NS, MX, TXT, CNAME)
func (s *SubdomainEnumerator) dnsRecordsEnum() {
	recordFuncs := []func(string) []string{
		dnsNS,
		dnsMX,
		dnsTXT,
		dnsCNAME,
	}
	for _, fn := range recordFuncs {
		for _, sub := range fn(s.Target) {
			s.foundSubdomains <- sub
		}
	}
}

func dnsNS(domain string) []string {
	var subs []string
	ns, _ := net.LookupNS(domain)
	for _, n := range ns {
		if strings.HasSuffix(n.Host, domain+".") {
			label := strings.TrimSuffix(n.Host, ".")
			if label != domain {
				subs = append(subs, label)
			}
		}
	}
	return subs
}

func dnsMX(domain string) []string {
	var subs []string
	mx, _ := net.LookupMX(domain)
	for _, m := range mx {
		if strings.HasSuffix(m.Host, domain+".") {
			label := strings.TrimSuffix(m.Host, ".")
			if label != domain {
				subs = append(subs, label)
			}
		}
	}
	return subs
}

func dnsTXT(domain string) []string {
	var subs []string
	txts, _ := net.LookupTXT(domain)
	for _, txt := range txts {
		subs = append(subs, extractSubdomains(txt, domain)...)
	}
	return subs
}

func dnsCNAME(domain string) []string {
	var subs []string
	cname, _ := net.LookupCNAME(domain)
	if strings.HasSuffix(cname, domain+".") {
		label := strings.TrimSuffix(cname, ".")
		if label != domain {
			subs = append(subs, label)
		}
	}
	return subs
}

// crtshEnum queries crt.sh for subdomains
func (s *SubdomainEnumerator) crtshEnum() {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", s.Target)
	resp, err := s.httpClient.Get(url)
	if err != nil {
		s.log.Warnf("crt.sh request failed: %v", err)
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	var data []map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		s.log.Warnf("crt.sh JSON parse failed: %v", err)
		return
	}
	for _, entry := range data {
		if name, ok := entry["name_value"].(string); ok {
			subs := extractSubdomains(name, s.Target)
			for _, sub := range subs {
				s.foundSubdomains <- sub
			}
		}
	}
}

// extractSubdomains finds subdomains of domain in text
func extractSubdomains(text, domain string) []string {
	re := regexp.MustCompile(`([a-zA-Z0-9_-]+\.` + regexp.QuoteMeta(domain) + `)`)
	return re.FindAllString(text, -1)
}

// isAlive checks if subdomain resolves (A/AAAA)
func (s *SubdomainEnumerator) isAlive(sub string) bool {
	_, err := net.LookupHost(sub)
	return err == nil
}
