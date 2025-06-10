// internal/modules/reconnaissance/favicon_hash.go
package reconnaissance

import (
	"apexPenetrateGo/internal/core"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type FaviconHashResult struct {
	Target     string
	Hash       int32
	MD5        string
	ShodanLink string
	CensysLink string
	Note       string
}

// mmh3 hash32 implementation (minimal, for favicon hash)
func mmh3Hash32(data []byte) int32 {
	var c1, c2 uint32 = 0xcc9e2d51, 0x1b873593
	var h1 uint32 = 0
	var length = len(data)
	var roundedEnd = (length & ^0x3)
	for i := 0; i < roundedEnd; i += 4 {
		k1 := uint32(data[i]) | uint32(data[i+1])<<8 | uint32(data[i+2])<<16 | uint32(data[i+3])<<24
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
		h1 = (h1 << 13) | (h1 >> 19)
		h1 = h1*5 + 0xe6546b64
	}
	k1 := uint32(0)
	switch length & 3 {
	case 3:
		k1 ^= uint32(data[roundedEnd+2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(data[roundedEnd+1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(data[roundedEnd])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
	}
	h1 ^= uint32(length)
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16
	return int32(h1)
}

func FaviconHash(target string) *FaviconHashResult {
	if !strings.HasPrefix(target, "http") {
		target = "http://" + target
	}
	faviconURL := target
	if !strings.HasSuffix(target, "/favicon.ico") {
		faviconURL = strings.TrimRight(target, "/") + "/favicon.ico"
	}
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get(faviconURL)
	if err != nil {
		return &FaviconHashResult{Target: target, Note: "Failed to fetch favicon: " + err.Error()}
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil || len(data) == 0 {
		return &FaviconHashResult{Target: target, Note: "Failed to read favicon data"}
	}
	b64 := base64.StdEncoding.EncodeToString(data)
	hash := mmh3Hash32([]byte(b64))
	md5sum := fmt.Sprintf("%x", md5.Sum(data))
	shodan := fmt.Sprintf("https://www.shodan.io/search?query=http.favicon.hash%%3A%d", hash)
	censys := fmt.Sprintf("https://search.censys.io/search?resource=hosts&q=http%%2Ffavicon.hash%%3A%d", hash)
	return &FaviconHashResult{
		Target:     target,
		Hash:       hash,
		MD5:        md5sum,
		ShodanLink: shodan,
		CensysLink: censys,
		Note:       "Use the links to find other assets with the same favicon.",
	}
}

func (r *FaviconHashResult) String() string {
	if r.Hash == 0 {
		return fmt.Sprintf("\n🖼️  Favicon Hash for %s: %s", r.Target, r.Note)
	}
	return fmt.Sprintf("\n🖼️  Favicon Hash for %s:\n  mmh3: %d\n  MD5: %s\n  Shodan: %s\n  Censys: %s\n  Note: %s\n", r.Target, r.Hash, r.MD5, r.ShodanLink, r.CensysLink, r.Note)
}

type faviconHashPlugin struct{}

func (p *faviconHashPlugin) Name() string { return "FaviconHash" }
func (p *faviconHashPlugin) Description() string {
	return "Fetches favicon, computes mmh3 hash, and provides Shodan/Censys links"
}
func (p *faviconHashPlugin) Run(target string, options map[string]interface{}) (interface{}, error) {
	return FaviconHash(target), nil
}
func (p *faviconHashPlugin) Category() string { return "recon" }
func (p *faviconHashPlugin) Options() []core.ModuleOption {
	return []core.ModuleOption{
		{Name: "favicon_path", Type: "string", Default: "/favicon.ico", Description: "Path to favicon file", Required: false},
		{Name: "timeout", Type: "string", Default: "8s", Description: "HTTP request timeout", Required: false},
	}
}
func (p *faviconHashPlugin) Help() string {
	return `
🖼️ Favicon Hash - Technology Fingerprinting via Favicon Analysis

DESCRIPTION:
  Calculates favicon hash to identify web technologies, frameworks, and applications
  based on their unique favicon signatures. Useful for passive reconnaissance.

USAGE:
  faviconhash <target_url> [options]

OPTIONS:
  timeout - HTTP request timeout (default: 8s)

EXAMPLES:
  faviconhash https://example.com
  faviconhash https://admin.example.com --timeout 10s
  faviconhash http://192.168.1.1:8080

TECHNOLOGY IDENTIFICATION:
  • Web Frameworks: Django, Rails, Spring, etc.
  • CMS Systems: WordPress, Drupal, Joomla
  • Applications: Jenkins, GitLab, Confluence
  • Network Devices: Routers, firewalls, switches
  • Development Tools: phpMyAdmin, Adminer

ATTACK SCENARIOS:
  • Technology Stack Discovery: Identify backend technologies
  • Default Installation Detection: Find unmodified installations
  • Version Fingerprinting: Narrow down specific versions
  • Attack Vector Selection: Choose exploits based on technology

HASH DATABASES:
  • Shodan Favicon Database
  • Custom Hash Collections
  • Open Source Signatures
  • Community Contributed Hashes

PRO TIPS:
  💡 Combine with other fingerprinting techniques for accuracy
  💡 Check multiple paths (/favicon.ico, /images/favicon.ico)
  💡 Look for custom favicons indicating specific applications
  💡 Cross-reference hashes with Shodan search results
  💡 Check favicon changes over time for version updates

PASSIVE RECONNAISSANCE:
  • No direct interaction with application logic
  • Low detection risk
  • Works even with basic access restrictions
  • Can identify hidden admin panels

COMMON FAVICON PATHS:
  • /favicon.ico (standard location)
  • /images/favicon.ico
  • /static/favicon.ico
  • /assets/favicon.ico
  • Custom paths in HTML head tags

RISK LEVEL: Low (passive information gathering)
`
}

func init() {
	core.RegisterPlugin(&faviconHashPlugin{})
}
