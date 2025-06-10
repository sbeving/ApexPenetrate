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

// ScanChain defines a sequence of modules with conditional execution
type ScanChain struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Steps       []ChainStep            `json:"steps"`
	Options     map[string]interface{} `json:"options"`
	OutputPath  string                 `json:"output_path"`
}

// ChainStep represents a single step in a scan chain
type ChainStep struct {
	Module      string                 `json:"module"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Options     map[string]interface{} `json:"options"`
	Conditions  []ChainCondition       `json:"conditions"`
	OnSuccess   []string               `json:"on_success"` // Next modules to run on success
	OnFailure   []string               `json:"on_failure"` // Next modules to run on failure
}

// ChainCondition defines when a step should execute
type ChainCondition struct {
	Type     string      `json:"type"`     // "result_contains", "ports_found", "vulns_found", etc.
	Value    interface{} `json:"value"`    // The value to check against
	Operator string      `json:"operator"` // "equals", "contains", "greater_than", etc.
}

// ChainExecution tracks the execution of a scan chain
type ChainExecution struct {
	Chain         ScanChain
	Results       map[string]interface{}
	ExecutedSteps []string
	StartTime     time.Time
	EndTime       time.Time
}

// AutomationEngine handles scheduled scans and profiles
type AutomationEngine struct {
	profiles  []ScanProfile
	chains    []ScanChain
	log       *logrus.Logger
	isRunning bool
	stopChan  chan bool
	reportGen *reporting.ReportGenerator
}

// NewAutomationEngine creates a new automation engine
func NewAutomationEngine() *AutomationEngine {
	return &AutomationEngine{
		profiles:  []ScanProfile{},
		chains:    []ScanChain{},
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

// AddChain adds a new scan chain
func (ae *AutomationEngine) AddChain(chain ScanChain) {
	ae.chains = append(ae.chains, chain)
	ae.log.Infof("Added scan chain: %s", chain.Name)
}

// ListChains returns all scan chains
func (ae *AutomationEngine) ListChains() []ScanChain {
	return ae.chains
}

// ExecuteChain executes a scan chain with conditional logic
func (ae *AutomationEngine) ExecuteChain(chainName, target string) (*ChainExecution, error) {
	// Find the chain
	var chain ScanChain
	found := false
	for _, c := range ae.chains {
		if c.Name == chainName {
			chain = c
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("chain not found: %s", chainName)
	}

	ae.log.Infof("🔗 Executing scan chain: %s on target: %s", chainName, target)

	execution := &ChainExecution{
		Chain:         chain,
		Results:       make(map[string]interface{}),
		ExecutedSteps: []string{},
		StartTime:     time.Now(),
	}

	// Initialize report generator
	ae.reportGen = reporting.NewReportGenerator()
	ae.reportGen.SetTarget(target)

	// Execute chain steps
	err := ae.executeChainSteps(execution, target)
	execution.EndTime = time.Now()

	if err != nil {
		ae.log.Errorf("Chain execution failed: %v", err)
		return execution, err
	}

	// Finalize and generate reports
	ae.reportGen.FinalizeScan()
	timestamp := time.Now().Format("20060102-150405")

	if chain.OutputPath != "" {
		htmlPath := fmt.Sprintf("%s/%s-chain-%s.html", chain.OutputPath, chainName, timestamp)
		jsonPath := fmt.Sprintf("%s/%s-chain-%s.json", chainName, chainName, timestamp)

		ae.reportGen.GenerateHTMLReport(htmlPath)
		ae.reportGen.GenerateJSONReport(jsonPath)
	}

	ae.log.Infof("✅ Chain execution completed: %s", chainName)
	return execution, nil
}

// executeChainSteps executes the steps in a chain with conditional logic
func (ae *AutomationEngine) executeChainSteps(execution *ChainExecution, target string) error {
	// Start with the first step
	if len(execution.Chain.Steps) == 0 {
		return fmt.Errorf("no steps defined in chain")
	}
	// Execute steps in order, checking conditions
	for _, step := range execution.Chain.Steps {
		// Check if step should be executed based on conditions
		if !ae.shouldExecuteStep(step, execution.Results) {
			ae.log.Infof("⏩ Skipping step %s (conditions not met)", step.Name)
			continue
		}

		ae.log.Infof("▶️ Executing step: %s (%s)", step.Name, step.Module)

		// Get the plugin
		plugin := GetPlugin(step.Module)
		if plugin == nil {
			ae.log.Warnf("⚠️ Module not found: %s", step.Module)
			continue
		}

		// Merge chain options with step options
		options := make(map[string]interface{})
		for k, v := range execution.Chain.Options {
			options[k] = v
		}
		for k, v := range step.Options {
			options[k] = v
		}
		options["target"] = target

		// Execute the module
		result, err := plugin.Run(target, options)
		if err != nil {
			ae.log.Errorf("❌ Step %s failed: %v", step.Name, err)

			// Handle failure - execute on_failure steps
			if len(step.OnFailure) > 0 {
				ae.log.Infof("🔄 Executing failure handlers for step %s", step.Name)
				// TODO: Implement failure handler execution
			}
			continue
		}

		// Store result
		execution.Results[step.Name] = result
		execution.ExecutedSteps = append(execution.ExecutedSteps, step.Name)
		ae.reportGen.AddModuleRun(step.Module)

		// Process result for vulnerabilities
		ae.processModuleResult(step.Module, result)

		ae.log.Infof("✅ Step %s completed successfully", step.Name)

		// Handle success - execute on_success steps if defined
		if len(step.OnSuccess) > 0 {
			ae.log.Infof("🎯 Triggering success handlers for step %s", step.Name)
			// TODO: Implement dynamic step execution based on success handlers
		}
	}

	return nil
}

// shouldExecuteStep checks if a step should be executed based on its conditions
func (ae *AutomationEngine) shouldExecuteStep(step ChainStep, results map[string]interface{}) bool {
	// If no conditions, always execute
	if len(step.Conditions) == 0 {
		return true
	}

	// Check all conditions (AND logic)
	for _, condition := range step.Conditions {
		if !ae.evaluateCondition(condition, results) {
			return false
		}
	}

	return true
}

// evaluateCondition evaluates a single condition
func (ae *AutomationEngine) evaluateCondition(condition ChainCondition, results map[string]interface{}) bool {
	switch condition.Type {
	case "result_contains":
		// Check if any result contains the specified value
		searchStr := fmt.Sprintf("%v", condition.Value)
		for _, result := range results {
			resultStr := fmt.Sprintf("%v", result)
			if strings.Contains(strings.ToLower(resultStr), strings.ToLower(searchStr)) {
				return true
			}
		}
		return false

	case "ports_found":
		// Check if open ports were found
		for _, result := range results {
			if m, ok := result.(map[string]interface{}); ok {
				if ports, ok := m["open_ports"]; ok && ports != nil {
					return true
				}
			}
		}
		return false

	case "vulns_found":
		// Check if vulnerabilities were found
		for _, result := range results {
			if m, ok := result.(map[string]interface{}); ok {
				if vulns, ok := m["vulnerabilities"]; ok && vulns != nil {
					return true
				}
			}
		}
		return false

	default:
		ae.log.Warnf("Unknown condition type: %s", condition.Type)
		return true
	}
}

// LoadChains loads scan chains from a JSON/YAML file
func (ae *AutomationEngine) LoadChains(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read chains file: %w", err)
	}

	var chains []ScanChain
	if err := json.Unmarshal(data, &chains); err != nil {
		return fmt.Errorf("failed to parse chains JSON: %w", err)
	}

	ae.chains = chains
	ae.log.Infof("Loaded %d scan chains from %s", len(chains), filename)
	return nil
}

// SaveChains saves scan chains to a JSON file
func (ae *AutomationEngine) SaveChains(filename string) error {
	data, err := json.MarshalIndent(ae.chains, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to marshal chains: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write chains file: %w", err)
	}

	ae.log.Infof("Saved %d scan chains to %s", len(ae.chains), filename)
	return nil
}

// CreateDefaultChains creates some default scan chains
func (ae *AutomationEngine) CreateDefaultChains() {
	// Smart reconnaissance chain
	smartRecon := ScanChain{
		Name:        "SmartRecon",
		Description: "Intelligent reconnaissance with conditional execution",
		Steps: []ChainStep{
			{
				Module:      "PortScan",
				Name:        "initial_port_scan",
				Description: "Initial port discovery",
				Options:     map[string]interface{}{"ports": "1-1000"},
				Conditions:  []ChainCondition{},
			},
			{
				Module:      "ServiceVersionDetect",
				Name:        "service_detection",
				Description: "Service version detection on open ports",
				Options:     map[string]interface{}{},
				Conditions: []ChainCondition{
					{Type: "ports_found", Value: true, Operator: "equals"},
				},
			},
			{
				Module:      "CVEScanner",
				Name:        "vulnerability_scan",
				Description: "CVE scanning on detected services",
				Options:     map[string]interface{}{},
				Conditions: []ChainCondition{
					{Type: "result_contains", Value: "service", Operator: "contains"},
				},
			},
		},
		Options:    map[string]interface{}{},
		OutputPath: "./reports",
	}

	// Web application chain
	webAppChain := ScanChain{
		Name:        "WebAppSecurity",
		Description: "Web application security assessment chain",
		Steps: []ChainStep{
			{
				Module:      "TechFingerprint",
				Name:        "tech_detection",
				Description: "Technology fingerprinting",
				Options:     map[string]interface{}{},
				Conditions:  []ChainCondition{},
			},
			{
				Module:      "DirFuzzer",
				Name:        "directory_fuzzing",
				Description: "Directory and file discovery",
				Options:     map[string]interface{}{},
				Conditions: []ChainCondition{
					{Type: "result_contains", Value: "web", Operator: "contains"},
				},
			},
			{
				Module:      "XSSScanner",
				Name:        "xss_testing",
				Description: "Cross-site scripting vulnerability testing",
				Options:     map[string]interface{}{},
				Conditions: []ChainCondition{
					{Type: "result_contains", Value: "found", Operator: "contains"},
				},
			},
			{
				Module:      "SQLIScanner",
				Name:        "sqli_testing",
				Description: "SQL injection vulnerability testing",
				Options:     map[string]interface{}{},
				Conditions: []ChainCondition{
					{Type: "result_contains", Value: "found", Operator: "contains"},
				},
			},
		},
		Options:    map[string]interface{}{},
		OutputPath: "./reports",
	}

	ae.AddChain(smartRecon)
	ae.AddChain(webAppChain)
}
