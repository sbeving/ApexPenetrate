// internal/modules/reconnaissance/os_detection.go
package reconnaissance

import (
	"apexPenetrateGo/internal/core"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type OSDetectionResult struct {
	Target          string
	OSGuess         string
	Confidence      int
	TTLValue        int
	WindowSize      int
	TCPFingerprint  string
	ServiceBanners  map[int]string
	AdditionalHints []string
}

// OSDetection performs OS fingerprinting using multiple techniques
func OSDetection(target string) *OSDetectionResult {
	result := &OSDetectionResult{
		Target:          target,
		ServiceBanners:  make(map[int]string),
		AdditionalHints: []string{},
	}

	// 1. TTL-based detection
	ttl := getTTLValue(target)
	result.TTLValue = ttl

	// 2. TCP Window Size detection (simplified)
	windowSize := getTCPWindowSize(target)
	result.WindowSize = windowSize

	// 3. Service banner analysis
	banners := getServiceBanners(target)
	result.ServiceBanners = banners

	// 4. Combine all hints to make an educated guess
	osGuess, confidence := analyzeFingerprints(ttl, windowSize, banners)
	result.OSGuess = osGuess
	result.Confidence = confidence

	// 5. Generate TCP fingerprint string
	result.TCPFingerprint = fmt.Sprintf("TTL:%d,WIN:%d", ttl, windowSize)

	// 6. Additional hints from banners
	for port, banner := range banners {
		if hint := extractOSHintFromBanner(banner); hint != "" {
			result.AdditionalHints = append(result.AdditionalHints, fmt.Sprintf("Port %d: %s", port, hint))
		}
	}

	return result
}

func getTTLValue(target string) int {
	// Try to ping the target and extract TTL value
	if runtime.GOOS == "windows" {
		return getTTLWindows(target)
	} else {
		return getTTLUnix(target)
	}
}

func getTTLWindows(target string) int {
	cmd := exec.Command("ping", "-n", "1", target)
	output, err := cmd.Output()
	if err != nil {
		return 0
	}

	// Parse Windows ping output for TTL
	re := regexp.MustCompile(`TTL=(\d+)`)
	matches := re.FindStringSubmatch(string(output))
	if len(matches) > 1 {
		if ttl, err := strconv.Atoi(matches[1]); err == nil {
			return ttl
		}
	}
	return 0
}

func getTTLUnix(target string) int {
	cmd := exec.Command("ping", "-c", "1", target)
	output, err := cmd.Output()
	if err != nil {
		return 0
	}

	// Parse Unix ping output for TTL
	re := regexp.MustCompile(`ttl=(\d+)`)
	matches := re.FindStringSubmatch(string(output))
	if len(matches) > 1 {
		if ttl, err := strconv.Atoi(matches[1]); err == nil {
			return ttl
		}
	}
	return 0
}

func getTCPWindowSize(target string) int {
	// Simplified TCP window size detection via HTTP connection
	conn, err := net.DialTimeout("tcp", target+":80", 3*time.Second)
	if err != nil {
		// Try port 443 if 80 fails
		conn, err = net.DialTimeout("tcp", target+":443", 3*time.Second)
		if err != nil {
			return 0
		}
	}
	defer conn.Close()

	// This is a simplified approach - real implementation would need raw sockets
	// to get actual TCP window size from packets
	return 65535 // Default assumption
}

func getServiceBanners(target string) map[int]string {
	banners := make(map[int]string)
	commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995}

	for _, port := range commonPorts {
		address := fmt.Sprintf("%s:%d", target, port)
		conn, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err != nil {
			continue
		}

		// Try to read banner
		buffer := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buffer)
		conn.Close()

		if err == nil && n > 0 {
			banner := strings.TrimSpace(string(buffer[:n]))
			if banner != "" {
				banners[port] = banner
			}
		}
	}

	return banners
}

func analyzeFingerprints(ttl, windowSize int, banners map[int]string) (string, int) {
	confidence := 0
	osGuesses := []string{}

	// TTL-based detection
	switch {
	case ttl >= 240 && ttl <= 255:
		osGuesses = append(osGuesses, "Windows (TTL ~255)")
		confidence += 30
	case ttl >= 60 && ttl <= 64:
		osGuesses = append(osGuesses, "Linux/Unix (TTL ~64)")
		confidence += 30
	case ttl >= 120 && ttl <= 128:
		osGuesses = append(osGuesses, "Windows (TTL ~128)")
		confidence += 25
	case ttl >= 30 && ttl <= 32:
		osGuesses = append(osGuesses, "Cisco/Network Device (TTL ~32)")
		confidence += 35
	}

	// Banner-based detection
	for _, banner := range banners {
		lowerBanner := strings.ToLower(banner)
		switch {
		case strings.Contains(lowerBanner, "microsoft"):
			osGuesses = append(osGuesses, "Windows (Microsoft banner)")
			confidence += 40
		case strings.Contains(lowerBanner, "ubuntu"):
			osGuesses = append(osGuesses, "Ubuntu Linux")
			confidence += 50
		case strings.Contains(lowerBanner, "centos"):
			osGuesses = append(osGuesses, "CentOS Linux")
			confidence += 50
		case strings.Contains(lowerBanner, "debian"):
			osGuesses = append(osGuesses, "Debian Linux")
			confidence += 50
		case strings.Contains(lowerBanner, "apache") && strings.Contains(lowerBanner, "unix"):
			osGuesses = append(osGuesses, "Unix/Linux (Apache)")
			confidence += 25
		case strings.Contains(lowerBanner, "iis"):
			osGuesses = append(osGuesses, "Windows (IIS)")
			confidence += 45
		case strings.Contains(lowerBanner, "openssh"):
			osGuesses = append(osGuesses, "Linux/Unix (OpenSSH)")
			confidence += 20
		}
	}

	// Combine guesses
	if len(osGuesses) == 0 {
		return "Unknown", 0
	}

	// Find most likely guess (simplified)
	guess := osGuesses[0]
	if confidence > 100 {
		confidence = 95 // Cap at 95%
	}

	return guess, confidence
}

func extractOSHintFromBanner(banner string) string {
	lowerBanner := strings.ToLower(banner)

	// Extract version information that might indicate OS
	patterns := map[string]string{
		"ubuntu":    "Ubuntu Linux detected",
		"centos":    "CentOS Linux detected",
		"debian":    "Debian Linux detected",
		"windows":   "Windows system detected",
		"microsoft": "Microsoft service detected",
		"cisco":     "Cisco device detected",
		"linux":     "Linux system detected",
		"freebsd":   "FreeBSD detected",
		"openbsd":   "OpenBSD detected",
		"macos":     "macOS detected",
	}

	for pattern, hint := range patterns {
		if strings.Contains(lowerBanner, pattern) {
			return hint
		}
	}

	return ""
}

func (r *OSDetectionResult) String() string {
	msg := fmt.Sprintf("\n🖥️  OS Detection Results for %s:\n", r.Target)
	msg += fmt.Sprintf("🎯 Best Guess: %s (Confidence: %d%%)\n", r.OSGuess, r.Confidence)
	msg += fmt.Sprintf("🔍 TCP Fingerprint: %s\n", r.TCPFingerprint)

	if r.TTLValue > 0 {
		msg += fmt.Sprintf("⏱️  TTL Value: %d\n", r.TTLValue)
	}

	if len(r.ServiceBanners) > 0 {
		msg += "\n📡 Service Banners:\n"
		for port, banner := range r.ServiceBanners {
			shortBanner := banner
			if len(banner) > 60 {
				shortBanner = banner[:60] + "..."
			}
			msg += fmt.Sprintf("  Port %d: %s\n", port, shortBanner)
		}
	}

	if len(r.AdditionalHints) > 0 {
		msg += "\n💡 Additional Hints:\n"
		for _, hint := range r.AdditionalHints {
			msg += fmt.Sprintf("  • %s\n", hint)
		}
	}

	return msg
}

type osDetectionPlugin struct{}

func (p *osDetectionPlugin) Name() string { return "OSDetection" }
func (p *osDetectionPlugin) Description() string {
	return "Performs OS fingerprinting using TTL, banners, and TCP characteristics"
}
func (p *osDetectionPlugin) Category() string { return "recon" }
func (p *osDetectionPlugin) Options() []core.ModuleOption {
	return []core.ModuleOption{
		{Name: "aggressive", Type: "bool", Default: false, Description: "Use aggressive detection methods", Required: false},
	}
}
func (p *osDetectionPlugin) Run(target string, options map[string]interface{}) (interface{}, error) {
	// For now, aggressive mode doesn't change behavior, but could be extended
	// to include nmap-style fingerprinting or other techniques

	return OSDetection(target), nil
}

func init() {
	core.RegisterPlugin(&osDetectionPlugin{})
}
