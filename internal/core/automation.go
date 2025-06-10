// internal/core/automation.go
package core

import (
	"apexPenetrateGo/internal/core/logger"
	"apexPenetrateGo/internal/reporting"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// ScanProfile defines a reusable scan configuration
type ScanProfile struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Modules     []string               `json:"modules"`
	Options     map[string]interface{} `json:"options"`
	Schedule    string                 `json:"schedule"` // Cron-like schedule
	OutputPath  string                 `json:"output_path"`
	Enabled     bool                   `json:"enabled"`
}

// AutomationEngine handles scheduled scans and profiles
type AutomationEngine struct {
	profiles  []ScanProfile
	log       *logrus.Logger
	isRunning bool
	stopChan  chan bool
	reportGen *reporting.ReportGenerator
}

// NewAutomationEngine creates a new automation engine
func NewAutomationEngine() *AutomationEngine {
	return &AutomationEngine{
		profiles:  []ScanProfile{},
		log:       logger.GetLogger(),
		isRunning: false,
		stopChan:  make(chan bool),
		reportGen: reporting.NewReportGenerator(),
	}
}

// AddProfile adds a new scan profile
func (ae *AutomationEngine) AddProfile(profile ScanProfile) {
	ae.profiles = append(ae.profiles, profile)
	ae.log.Infof("Added scan profile: %s", profile.Name)
}

// RemoveProfile removes a scan profile by name
func (ae *AutomationEngine) RemoveProfile(name string) bool {
	for i, profile := range ae.profiles {
		if profile.Name == name {
			ae.profiles = append(ae.profiles[:i], ae.profiles[i+1:]...)
			ae.log.Infof("Removed scan profile: %s", name)
			return true
		}
	}
	return false
}

// ListProfiles returns all scan profiles
func (ae *AutomationEngine) ListProfiles() []ScanProfile {
	return ae.profiles
}

// LoadProfiles loads scan profiles from a JSON file
func (ae *AutomationEngine) LoadProfiles(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read profiles file: %w", err)
	}

	var profiles []ScanProfile
	if err := json.Unmarshal(data, &profiles); err != nil {
		return fmt.Errorf("failed to parse profiles JSON: %w", err)
	}

	ae.profiles = profiles
	ae.log.Infof("Loaded %d scan profiles from %s", len(profiles), filename)
	return nil
}

// SaveProfiles saves scan profiles to a JSON file
func (ae *AutomationEngine) SaveProfiles(filename string) error {
	data, err := json.MarshalIndent(ae.profiles, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to marshal profiles: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write profiles file: %w", err)
	}

	ae.log.Infof("Saved %d scan profiles to %s", len(ae.profiles), filename)
	return nil
}

// Start begins the automation engine scheduler
func (ae *AutomationEngine) Start() {
	if ae.isRunning {
		ae.log.Warn("Automation engine is already running")
		return
	}

	ae.isRunning = true
	ae.log.Info("🤖 Starting automation engine...")

	go ae.scheduler()
}

// Stop stops the automation engine
func (ae *AutomationEngine) Stop() {
	if !ae.isRunning {
		ae.log.Warn("Automation engine is not running")
		return
	}

	ae.log.Info("Stopping automation engine...")
	ae.stopChan <- true
	ae.isRunning = false
}

// scheduler runs the main scheduling loop
func (ae *AutomationEngine) scheduler() {
	ticker := time.NewTicker(1 * time.Minute) // Check every minute
	defer ticker.Stop()

	for {
		select {
		case <-ae.stopChan:
			ae.log.Info("Automation engine stopped")
			return
		case <-ticker.C:
			ae.checkScheduledScans()
		}
	}
}

// checkScheduledScans checks if any profiles need to be executed
func (ae *AutomationEngine) checkScheduledScans() {
	now := time.Now()

	for _, profile := range ae.profiles {
		if !profile.Enabled {
			continue
		}

		if ae.shouldRunNow(profile.Schedule, now) {
			ae.log.Infof("⏰ Executing scheduled scan: %s", profile.Name)
			go ae.executeProfile(profile)
		}
	}
}

// shouldRunNow determines if a profile should run based on its schedule
func (ae *AutomationEngine) shouldRunNow(schedule string, now time.Time) bool {
	// Simple schedule parsing - extend this for full cron support
	switch schedule {
	case "hourly":
		return now.Minute() == 0
	case "daily":
		return now.Hour() == 0 && now.Minute() == 0
	case "weekly":
		return now.Weekday() == time.Monday && now.Hour() == 0 && now.Minute() == 0
	case "monthly":
		return now.Day() == 1 && now.Hour() == 0 && now.Minute() == 0
	default:
		// Custom time format: "15:04" for daily at specific time
		if len(schedule) == 5 && schedule[2] == ':' {
			targetTime := fmt.Sprintf("%02d:%02d", now.Hour(), now.Minute())
			return schedule == targetTime
		}
	}
	return false
}

// executeProfile runs a scan profile
func (ae *AutomationEngine) executeProfile(profile ScanProfile) {
	ae.log.Infof("🚀 Executing profile: %s", profile.Name)

	// Initialize report generator
	ae.reportGen = reporting.NewReportGenerator()
	ae.reportGen.SetTarget("automated-scan")

	// Execute each module in the profile
	for _, moduleName := range profile.Modules {
		ae.log.Infof("Running module: %s", moduleName)

		plugin := GetPlugin(moduleName)
		if plugin == nil {
			ae.log.Warnf("Module not found: %s", moduleName)
			continue
		}

		// Extract target from profile options
		target, ok := profile.Options["target"].(string)
		if !ok {
			ae.log.Warn("No target specified in profile options")
			continue
		}

		// Run the module
		result, err := plugin.Run(target, profile.Options)
		if err != nil {
			ae.log.Errorf("Module %s failed: %v", moduleName, err)
			continue
		}

		ae.reportGen.AddModuleRun(moduleName)

		// Convert result to vulnerability if applicable
		ae.processModuleResult(moduleName, result)
	}

	// Generate report
	ae.reportGen.FinalizeScan()

	// Save reports
	timestamp := time.Now().Format("20060102-150405")
	htmlPath := fmt.Sprintf("%s/%s-report-%s.html", profile.OutputPath, profile.Name, timestamp)
	jsonPath := fmt.Sprintf("%s/%s-report-%s.json", profile.OutputPath, profile.Name, timestamp)

	if err := ae.reportGen.GenerateHTMLReport(htmlPath); err != nil {
		ae.log.Errorf("Failed to generate HTML report: %v", err)
	}

	if err := ae.reportGen.GenerateJSONReport(jsonPath); err != nil {
		ae.log.Errorf("Failed to generate JSON report: %v", err)
	}

	ae.log.Infof("✅ Profile execution completed: %s", profile.Name)
}

// processModuleResult converts module results to vulnerabilities
func (ae *AutomationEngine) processModuleResult(moduleName string, result interface{}) {
	// This is a simplified example - in practice, you'd need more sophisticated
	// result parsing based on the specific module output format

	// For now, we'll create a generic vulnerability for any non-nil result
	if result != nil {
		resultStr := fmt.Sprintf("%v", result)

		// Check if the result indicates vulnerabilities
		if strings.Contains(strings.ToLower(resultStr), "vulnerable") ||
			strings.Contains(strings.ToLower(resultStr), "found") ||
			strings.Contains(strings.ToLower(resultStr), "detected") {

			var severity string
			var cvss float64

			// Determine severity based on module type
			switch moduleName {
			case "CVEScanner":
				severity = "HIGH"
				cvss = 7.5
			case "XSSScanner", "SQLIScanner":
				severity = "MEDIUM"
				cvss = 6.1
			case "OpenRedirect", "CORSTester":
				severity = "LOW"
				cvss = 4.3
			default:
				severity = "MEDIUM"
				cvss = 5.0
			}

			vuln := reporting.Vulnerability{
				Title:       fmt.Sprintf("%s Finding", moduleName),
				Severity:    severity,
				CVSS:        cvss,
				Description: fmt.Sprintf("Security issue detected by %s module", moduleName),
				Impact:      "Potential security vulnerability",
				Remediation: "Review and remediate the identified issue",
				Module:      moduleName,
				Evidence:    resultStr[:min(len(resultStr), 200)], // Truncate for display
			}
			ae.reportGen.AddVulnerability(vuln)
		}
	}
}

// Helper function for minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// CreateDefaultProfiles creates some default scan profiles
func (ae *AutomationEngine) CreateDefaultProfiles() {
	// Quick recon profile
	quickRecon := ScanProfile{
		Name:        "QuickRecon",
		Description: "Fast reconnaissance scan",
		Modules:     []string{"PortScan", "ServiceVersionDetect", "TechFingerprint"},
		Options: map[string]interface{}{
			"target": "127.0.0.1",
			"ports":  "80,443,22,21,25,53,110,995,993,143",
		},
		Schedule:   "daily",
		OutputPath: "./reports",
		Enabled:    false,
	}

	// Comprehensive security scan
	fullScan := ScanProfile{
		Name:        "FullSecurityScan",
		Description: "Comprehensive security assessment",
		Modules: []string{
			"PortScan", "ServiceVersionDetect", "CVEScanner", "OSDetection",
			"XSSScanner", "SQLIScanner", "DirFuzzer", "CORSTester",
		},
		Options: map[string]interface{}{
			"target": "127.0.0.1",
		},
		Schedule:   "weekly",
		OutputPath: "./reports",
		Enabled:    false,
	}

	// Web application focused scan
	webAppScan := ScanProfile{
		Name:        "WebAppScan",
		Description: "Web application security scan",
		Modules: []string{
			"TechFingerprint", "DirFuzzer", "XSSScanner", "SQLIScanner",
			"CORSTester", "OpenRedirect", "SSRFScanner", "XXEScanner",
		},
		Options: map[string]interface{}{
			"target": "http://127.0.0.1",
		},
		Schedule:   "08:00",
		OutputPath: "./reports",
		Enabled:    false,
	}

	ae.AddProfile(quickRecon)
	ae.AddProfile(fullScan)
	ae.AddProfile(webAppScan)
}
