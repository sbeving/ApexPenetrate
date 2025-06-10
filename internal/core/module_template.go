// internal/core/module_template.go
package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

// ModuleTemplateType represents different types of module templates
type ModuleTemplateType string

const (
	TemplateReconnaissance ModuleTemplateType = "reconnaissance"
	TemplateWebVulns       ModuleTemplateType = "web_vulnerabilities"
	TemplateNetworkVulns   ModuleTemplateType = "network_vulnerabilities"
	TemplateExploit        ModuleTemplateType = "exploit"
	TemplatePostExploit    ModuleTemplateType = "post_exploit"
	TemplateCustom         ModuleTemplateType = "custom"
)

// ModuleTemplateConfig defines the configuration for generating a module
type ModuleTemplateConfig struct {
	ModuleName        string             `json:"module_name"`
	PackageName       string             `json:"package_name"`
	Description       string             `json:"description"`
	Author            string             `json:"author"`
	Category          string             `json:"category"`
	Type              ModuleTemplateType `json:"type"`
	HasOptions        bool               `json:"has_options"`
	HasHelp           bool               `json:"has_help"`
	HasTests          bool               `json:"has_tests"`
	Dependencies      []string           `json:"dependencies"`
	OutputPath        string             `json:"output_path"`
	CustomFields      map[string]string  `json:"custom_fields"`
}

// ModuleGenerator generates new modules from templates
type ModuleGenerator struct {
	templates map[ModuleTemplateType]*template.Template
	outputDir string
}

// NewModuleGenerator creates a new module generator
func NewModuleGenerator(outputDir string) *ModuleGenerator {
	if outputDir == "" {
		outputDir = "./internal/modules"
	}

	mg := &ModuleGenerator{
		templates: make(map[ModuleTemplateType]*template.Template),
		outputDir: outputDir,
	}

	mg.loadTemplates()
	return mg
}

// loadTemplates loads all module templates
func (mg *ModuleGenerator) loadTemplates() {
	// Reconnaissance module template
	reconTemplate := `// internal/modules/reconnaissance/{{.PackageName}}.go
package reconnaissance

import (
	"apexPenetrateGo/internal/core"
	"fmt"
	"time"
{{- range .Dependencies}}
	"{{.}}"
{{- end}}
)

// {{.StructName}}Result represents the results of {{.ModuleName}} scanning
type {{.StructName}}Result struct {
	Target      string            ` + "`json:\"target\"`" + `
	Success     bool              ` + "`json:\"success\"`" + `
	Results     []string          ` + "`json:\"results\"`" + `
	Metadata    map[string]string ` + "`json:\"metadata\"`" + `
	ExecutionTime time.Duration   ` + "`json:\"execution_time\"`" + `
	Timestamp   time.Time         ` + "`json:\"timestamp\"`" + `
}

// {{.FunctionName}} performs {{.Description}}
func {{.FunctionName}}(target string{{if .HasOptions}}, options map[string]interface{}{{end}}) *{{.StructName}}Result {
	startTime := time.Now()
	
	result := &{{.StructName}}Result{
		Target:    target,
		Success:   false,
		Results:   []string{},
		Metadata:  make(map[string]string),
		Timestamp: time.Now(),
	}

	// TODO: Implement your scanning logic here
	// Example:
	// if target != "" {
	//     result.Results = append(result.Results, "Sample result for " + target)
	//     result.Success = true
	// }

	result.ExecutionTime = time.Since(startTime)
	return result
}

// String returns a string representation of the results
func (r *{{.StructName}}Result) String() string {
	status := "❌"
	if r.Success {
		status = "✅"
	}

	msg := fmt.Sprintf("\n%s {{.ModuleName}} for %s:\n", status, r.Target)
	msg += fmt.Sprintf("  📊 Results found: %d\n", len(r.Results))
	msg += fmt.Sprintf("  ⏱️  Execution time: %s\n", r.ExecutionTime)

	if r.Success {
		for i, result := range r.Results {
			msg += fmt.Sprintf("    %d. %s\n", i+1, result)
		}
	} else {
		msg += "  ℹ️  No results found\n"
	}

	return msg
}

// {{.PluginStructName}} implements the Plugin interface
type {{.PluginStructName}} struct{}

func (p *{{.PluginStructName}}) Name() string {
	return "{{.ModuleName}}"
}

func (p *{{.PluginStructName}}) Description() string {
	return "{{.Description}}"
}

func (p *{{.PluginStructName}}) Category() string {
	return "{{.Category}}"
}

{{if .HasOptions}}
func (p *{{.PluginStructName}}) Options() []core.ModuleOption {
	return []core.ModuleOption{
		{
			Name:        "timeout",
			Type:        "string",
			Default:     "30s",
			Description: "Timeout for operations (e.g., 30s, 1m)",
			Required:    false,
		},
		// TODO: Add your module-specific options here
		// Example:
		// {
		//     Name:        "custom_option",
		//     Type:        "string",
		//     Default:     "",
		//     Description: "Custom option description",
		//     Required:    false,
		// },
	}
}
{{else}}
func (p *{{.PluginStructName}}) Options() []core.ModuleOption {
	return []core.ModuleOption{}
}
{{end}}

{{if .HasHelp}}
func (p *{{.PluginStructName}}) Help() string {
	return ` + "`" + `
🔍 {{.ModuleName}} Module - {{.Description}}

📋 DESCRIPTION:
   {{.Description}}

🎯 USAGE:
   apex> use {{.ModuleName}}
   apex> set target example.com
   apex> run

📊 EXAMPLES:
   • Basic scan:
     target=example.com
   
   • Advanced scan with options:
     target=example.com timeout=60s

⚙️ OPTIONS:
   target   [REQUIRED] - Target to scan
{{if .HasOptions}}   timeout  [OPTIONAL] - Operation timeout (default: 30s){{end}}

📈 OUTPUT:
   • Scan results and findings
   • Execution time and metadata
   • Success/failure status

💡 PRO TIPS:
   → Use appropriate timeouts for better results
   → Combine with other reconnaissance modules
   → Check target availability before scanning

🚨 NOTES:
   → Ensure you have permission to scan the target
   → Follow responsible disclosure practices
   → Consider rate limiting for external targets

⚡ AUTOMATION:
   Perfect for automated reconnaissance workflows.
   Chain with other modules for comprehensive scanning.
` + "`" + `
}
{{else}}
func (p *{{.PluginStructName}}) Help() string {
	return "{{.ModuleName}} - {{.Description}}"
}
{{end}}

func (p *{{.PluginStructName}}) Run(target string, options map[string]interface{}) (interface{}, error) {
	if target == "" {
		return nil, fmt.Errorf("target is required")
	}

	result := {{.FunctionName}}(target{{if .HasOptions}}, options{{end}})
	return result, nil
}

func init() {
	core.RegisterPlugin(&{{.PluginStructName}}{})
}
`

	// Web vulnerabilities module template
	webTemplate := `// internal/modules/web_vulnerabilities/{{.PackageName}}.go
package web_vulnerabilities

import (
	"apexPenetrateGo/internal/core"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
{{- range .Dependencies}}
	"{{.}}"
{{- end}}
)

// {{.StructName}}Result represents the results of {{.ModuleName}} scanning
type {{.StructName}}Result struct {
	Target          string                    ` + "`json:\"target\"`" + `
	Vulnerable      bool                      ` + "`json:\"vulnerable\"`" + `
	Vulnerabilities []{{.StructName}}Vuln     ` + "`json:\"vulnerabilities\"`" + `
	TestedPayloads  []string                  ` + "`json:\"tested_payloads\"`" + `
	Note            string                    ` + "`json:\"note\"`" + `
	ExecutionTime   time.Duration             ` + "`json:\"execution_time\"`" + `
	Timestamp       time.Time                 ` + "`json:\"timestamp\"`" + `
}

// {{.StructName}}Vuln represents a single vulnerability finding
type {{.StructName}}Vuln struct {
	Parameter    string ` + "`json:\"parameter\"`" + `
	Payload      string ` + "`json:\"payload\"`" + `
	URL          string ` + "`json:\"url\"`" + `
	Method       string ` + "`json:\"method\"`" + `
	StatusCode   int    ` + "`json:\"status_code\"`" + `
	ResponseTime time.Duration ` + "`json:\"response_time\"`" + `
	Evidence     string ` + "`json:\"evidence\"`" + `
}

// Common test payloads for {{.ModuleName}}
var {{.LowerName}}Payloads = []string{
	// TODO: Add your vulnerability-specific payloads here
	"test_payload_1",
	"test_payload_2",
	"test_payload_3",
}

// {{.FunctionName}} performs {{.Description}}
func {{.FunctionName}}(target string{{if .HasOptions}}, options map[string]interface{}{{end}}) *{{.StructName}}Result {
	startTime := time.Now()
	
	if !strings.HasPrefix(target, "http") {
		target = "http://" + target
	}

	result := &{{.StructName}}Result{
		Target:          target,
		Vulnerable:      false,
		Vulnerabilities: []{{.StructName}}Vuln{},
		TestedPayloads:  []string{},
		Timestamp:       time.Now(),
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	// TODO: Implement your vulnerability testing logic here
	for _, payload := range {{.LowerName}}Payloads {
		result.TestedPayloads = append(result.TestedPayloads, payload)
		
		// Example testing logic:
		testURL := target + "?test=" + url.QueryEscape(payload)
		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// TODO: Add your vulnerability detection logic
		// if isVulnerable(resp, payload) {
		//     vuln := {{.StructName}}Vuln{
		//         Parameter:  "test",
		//         Payload:    payload,
		//         URL:        testURL,
		//         Method:     "GET",
		//         StatusCode: resp.StatusCode,
		//         Evidence:   "Vulnerability detected",
		//     }
		//     result.Vulnerabilities = append(result.Vulnerabilities, vuln)
		//     result.Vulnerable = true
		// }
	}

	if result.Vulnerable {
		result.Note = fmt.Sprintf("Found %d {{.ModuleName}} vulnerabilities", len(result.Vulnerabilities))
	} else {
		result.Note = "No {{.ModuleName}} vulnerabilities detected"
	}

	result.ExecutionTime = time.Since(startTime)
	return result
}

// String returns a string representation of the results
func (r *{{.StructName}}Result) String() string {
	status := "🔒"
	if r.Vulnerable {
		status = "🚨"
	}

	msg := fmt.Sprintf("\n%s {{.ModuleName}} Scanner for %s:\n", status, r.Target)
	msg += fmt.Sprintf("  🧪 Payloads tested: %d\n", len(r.TestedPayloads))
	msg += fmt.Sprintf("  ⏱️  Execution time: %s\n", r.ExecutionTime)

	if r.Vulnerable {
		msg += fmt.Sprintf("  🚨 VULNERABLE: Found %d issues:\n", len(r.Vulnerabilities))
		for i, vuln := range r.Vulnerabilities {
			msg += fmt.Sprintf("    %d. Parameter: %s [%s]\n", i+1, vuln.Parameter, vuln.Method)
			msg += fmt.Sprintf("       Payload: %s\n", vuln.Payload)
			msg += fmt.Sprintf("       Evidence: %s\n", vuln.Evidence)
		}
	} else {
		msg += "  ✅ No {{.ModuleName}} vulnerabilities found\n"
	}

	msg += fmt.Sprintf("  📝 Note: %s\n", r.Note)
	return msg
}

// {{.PluginStructName}} implements the Plugin interface
type {{.PluginStructName}} struct{}

func (p *{{.PluginStructName}}) Name() string {
	return "{{.ModuleName}}"
}

func (p *{{.PluginStructName}}) Description() string {
	return "{{.Description}}"
}

func (p *{{.PluginStructName}}) Category() string {
	return "web"
}

{{if .HasOptions}}
func (p *{{.PluginStructName}}) Options() []core.ModuleOption {
	return []core.ModuleOption{
		{
			Name:        "payload",
			Type:        "string",
			Default:     "",
			Description: "Custom payload to test (leave blank for all)",
			Required:    false,
		},
		{
			Name:        "method",
			Type:        "string",
			Default:     "GET",
			Description: "HTTP method to use (GET/POST)",
			Required:    false,
		},
		{
			Name:        "timeout",
			Type:        "string",
			Default:     "15s",
			Description: "Request timeout (e.g., 15s)",
			Required:    false,
		},
		// TODO: Add your module-specific options here
	}
}
{{else}}
func (p *{{.PluginStructName}}) Options() []core.ModuleOption {
	return []core.ModuleOption{}
}
{{end}}

{{if .HasHelp}}
func (p *{{.PluginStructName}}) Help() string {
	return ` + "`" + `
🔍 {{.ModuleName}} Module - {{.Description}}

📋 DESCRIPTION:
   {{.Description}}

🎯 USAGE:
   apex> use {{.ModuleName}}
   apex> set target http://example.com
   apex> run

📊 EXAMPLES:
   • Basic scan:
     target=http://example.com
   
   • Custom payload testing:
     target=http://example.com payload=custom_test

⚙️ OPTIONS:
   target   [REQUIRED] - Target URL to test
{{if .HasOptions}}   payload  [OPTIONAL] - Custom payload to test
   method   [OPTIONAL] - HTTP method (GET/POST)
   timeout  [OPTIONAL] - Request timeout{{end}}

🔧 DETECTION:
   • Response analysis
   • Error message detection
   • Timing analysis
   • Content verification

📈 OUTPUT:
   • Vulnerability details
   • Payload information
   • Evidence and proof of concept
   • Remediation recommendations

💡 PRO TIPS:
   → Test multiple payloads for comprehensive coverage
   → Use both GET and POST methods
   → Check for different vulnerability contexts
   → Combine with other web scanners

🚨 SEVERITY:
   🔴 HIGH - Direct security impact
   🟡 MEDIUM - Potential security risk
   🟢 LOW - Information disclosure

⚡ AUTOMATION:
   Perfect for web application security assessments.
   Chain with directory fuzzing and parameter discovery.
` + "`" + `
}
{{else}}
func (p *{{.PluginStructName}}) Help() string {
	return "{{.ModuleName}} - {{.Description}}"
}
{{end}}

func (p *{{.PluginStructName}}) Run(target string, options map[string]interface{}) (interface{}, error) {
	if target == "" {
		return nil, fmt.Errorf("target URL is required")
	}

	result := {{.FunctionName}}(target{{if .HasOptions}}, options{{end}})
	return result, nil
}

func init() {
	core.RegisterPlugin(&{{.PluginStructName}}{})
}
`

	// Parse templates
	mg.templates[TemplateReconnaissance] = template.Must(template.New("reconnaissance").Parse(reconTemplate))
	mg.templates[TemplateWebVulns] = template.Must(template.New("web_vulnerabilities").Parse(webTemplate))
}

// GenerateModule generates a new module from a template
func (mg *ModuleGenerator) GenerateModule(config ModuleTemplateConfig) error {
	// Set defaults
	if config.Author == "" {
		config.Author = "ApexPenetrate Developer"
	}
	if config.PackageName == "" {
		config.PackageName = strings.ToLower(strings.ReplaceAll(config.ModuleName, " ", "_"))
	}

	// Prepare template data
	templateData := mg.prepareTemplateData(config)

	// Get template
	tmpl, exists := mg.templates[config.Type]
	if !exists {
		return fmt.Errorf("template type %s not found", config.Type)
	}

	// Determine output path
	var outputPath string
	if config.OutputPath != "" {
		outputPath = config.OutputPath
	} else {
		switch config.Type {
		case TemplateReconnaissance:
			outputPath = filepath.Join(mg.outputDir, "reconnaissance", config.PackageName+".go")
		case TemplateWebVulns:
			outputPath = filepath.Join(mg.outputDir, "web_vulnerabilities", config.PackageName+".go")
		case TemplateNetworkVulns:
			outputPath = filepath.Join(mg.outputDir, "network_vulnerabilities", config.PackageName+".go")
		default:
			outputPath = filepath.Join(mg.outputDir, "custom", config.PackageName+".go")
		}
	}

	// Create output directory
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate file
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	// Execute template
	if err := tmpl.Execute(file, templateData); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	// Generate test file if requested
	if config.HasTests {
		if err := mg.generateTestFile(config, templateData); err != nil {
			return fmt.Errorf("failed to generate test file: %w", err)
		}
	}

	fmt.Printf("✅ Generated module: %s\n", outputPath)
	if config.HasTests {
		fmt.Printf("✅ Generated test file: %s\n", strings.Replace(outputPath, ".go", "_test.go", 1))
	}

	return nil
}

// prepareTemplateData prepares data for template execution
func (mg *ModuleGenerator) prepareTemplateData(config ModuleTemplateConfig) map[string]interface{} {
	data := make(map[string]interface{})

	// Basic fields
	data["ModuleName"] = config.ModuleName
	data["PackageName"] = config.PackageName
	data["Description"] = config.Description
	data["Author"] = config.Author
	data["Category"] = config.Category
	data["HasOptions"] = config.HasOptions
	data["HasHelp"] = config.HasHelp
	data["HasTests"] = config.HasTests
	data["Dependencies"] = config.Dependencies

	// Derived fields
	data["StructName"] = mg.toStructName(config.ModuleName)
	data["FunctionName"] = mg.toFunctionName(config.ModuleName)
	data["PluginStructName"] = mg.toPluginStructName(config.ModuleName)
	data["LowerName"] = strings.ToLower(config.ModuleName)

	// Custom fields
	for key, value := range config.CustomFields {
		data[key] = value
	}

	return data
}

// generateTestFile generates a test file for the module
func (mg *ModuleGenerator) generateTestFile(config ModuleTemplateConfig, templateData map[string]interface{}) error {
	testTemplate := `// internal/modules/{{.Category}}/{{.PackageName}}_test.go
package {{.Category}}

import (
	"testing"
	"time"
)

func Test{{.StructName}}(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		expected bool
	}{
		{
			name:     "Valid target",
			target:   "example.com",
			expected: true,
		},
		{
			name:     "Empty target",
			target:   "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := {{.FunctionName}}(tt.target{{if .HasOptions}}, nil{{end}})
			
			if result == nil {
				t.Errorf("{{.FunctionName}}() returned nil")
				return
			}

			if result.Target != tt.target {
				t.Errorf("Expected target %s, got %s", tt.target, result.Target)
			}

			if result.ExecutionTime <= 0 {
				t.Errorf("Expected positive execution time, got %s", result.ExecutionTime)
			}

			if result.Timestamp.IsZero() {
				t.Errorf("Expected non-zero timestamp")
			}
		})
	}
}

func Test{{.StructName}}String(t *testing.T) {
	result := &{{.StructName}}Result{
		Target:        "example.com",
		Success:       true,
		Results:       []string{"test result"},
		ExecutionTime: time.Second,
		Timestamp:     time.Now(),
	}

	output := result.String()
	if output == "" {
		t.Errorf("String() returned empty output")
	}

	if !strings.Contains(output, "example.com") {
		t.Errorf("String() output should contain target name")
	}
}

func Test{{.PluginStructName}}(t *testing.T) {
	plugin := &{{.PluginStructName}}{}

	if plugin.Name() != "{{.ModuleName}}" {
		t.Errorf("Expected name {{.ModuleName}}, got %s", plugin.Name())
	}

	if plugin.Category() != "{{.Category}}" {
		t.Errorf("Expected category {{.Category}}, got %s", plugin.Category())
	}

	if plugin.Description() == "" {
		t.Errorf("Description should not be empty")
	}

	options := plugin.Options()
	if options == nil {
		t.Errorf("Options() should not return nil")
	}

	help := plugin.Help()
	if help == "" {
		t.Errorf("Help() should not return empty string")
	}
}

func Test{{.PluginStructName}}Run(t *testing.T) {
	plugin := &{{.PluginStructName}}{}

	// Test with empty target
	_, err := plugin.Run("", nil)
	if err == nil {
		t.Errorf("Expected error for empty target")
	}

	// Test with valid target
	result, err := plugin.Run("example.com", nil)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if result == nil {
		t.Errorf("Result should not be nil")
	}
}
`

	tmpl := template.Must(template.New("test").Parse(testTemplate))

	// Determine test file path
	testPath := strings.Replace(
		filepath.Join(mg.outputDir, config.Category, config.PackageName+".go"),
		".go",
		"_test.go",
		1,
	)

	file, err := os.Create(testPath)
	if err != nil {
		return fmt.Errorf("failed to create test file: %w", err)
	}
	defer file.Close()

	return tmpl.Execute(file, templateData)
}

// Utility functions for name conversion
func (mg *ModuleGenerator) toStructName(name string) string {
	parts := strings.Fields(name)
	for i, part := range parts {
		parts[i] = strings.Title(part)
	}
	return strings.Join(parts, "")
}

func (mg *ModuleGenerator) toFunctionName(name string) string {
	return mg.toStructName(name)
}

func (mg *ModuleGenerator) toPluginStructName(name string) string {
	return strings.ToLower(mg.toStructName(name)) + "Plugin"
}

// ListTemplates returns available module templates
func (mg *ModuleGenerator) ListTemplates() []ModuleTemplateType {
	var templates []ModuleTemplateType
	for templateType := range mg.templates {
		templates = append(templates, templateType)
	}
	return templates
}

// GetTemplateInfo returns information about a specific template
func (mg *ModuleGenerator) GetTemplateInfo(templateType ModuleTemplateType) map[string]interface{} {
	info := make(map[string]interface{})

	switch templateType {
	case TemplateReconnaissance:
		info["name"] = "Reconnaissance Module"
		info["description"] = "Template for network and service reconnaissance modules"
		info["category"] = "reconnaissance"
		info["features"] = []string{"Target scanning", "Result collection", "Plugin interface"}
	case TemplateWebVulns:
		info["name"] = "Web Vulnerability Scanner"
		info["description"] = "Template for web application vulnerability scanners"
		info["category"] = "web"
		info["features"] = []string{"HTTP testing", "Payload execution", "Vulnerability detection"}
	case TemplateNetworkVulns:
		info["name"] = "Network Vulnerability Scanner"
		info["description"] = "Template for network-level vulnerability scanners"
		info["category"] = "network"
		info["features"] = []string{"Network scanning", "Service testing", "Protocol analysis"}
	default:
		info["name"] = "Unknown Template"
		info["description"] = "Template information not available"
	}

	return info
}

// ValidateConfig validates module generation configuration
func (mg *ModuleGenerator) ValidateConfig(config ModuleTemplateConfig) []string {
	var errors []string

	if config.ModuleName == "" {
		errors = append(errors, "Module name is required")
	}

	if config.Description == "" {
		errors = append(errors, "Module description is required")
	}

	if config.Category == "" {
		errors = append(errors, "Module category is required")
	}

	// Check if template exists
	if _, exists := mg.templates[config.Type]; !exists {
		errors = append(errors, fmt.Sprintf("Template type %s not found", config.Type))
	}

	// Validate module name format
	if strings.Contains(config.ModuleName, " ") && config.PackageName == "" {
		// This is okay, we'll generate package name automatically
	}

	return errors
}

// GenerateScaffold generates a complete module scaffold with multiple files
func (mg *ModuleGenerator) GenerateScaffold(config ModuleTemplateConfig) error {
	// Validate configuration
	if errors := mg.ValidateConfig(config); len(errors) > 0 {
		return fmt.Errorf("validation errors: %v", errors)
	}

	// Generate main module file
	if err := mg.GenerateModule(config); err != nil {
		return fmt.Errorf("failed to generate module: %w", err)
	}

	// Generate additional files if requested
	if config.HasTests {
		// Test file is already generated in GenerateModule
	}

	// Generate documentation file
	if err := mg.generateDocumentation(config); err != nil {
		return fmt.Errorf("failed to generate documentation: %w", err)
	}

	// Generate example usage file
	if err := mg.generateExample(config); err != nil {
		return fmt.Errorf("failed to generate example: %w", err)
	}

	return nil
}

// generateDocumentation generates a README file for the module
func (mg *ModuleGenerator) generateDocumentation(config ModuleTemplateConfig) error {
	docTemplate := `# {{.ModuleName}} Module

## Description
{{.Description}}

## Author
{{.Author}}

## Category
{{.Category}}

## Usage

### Basic Usage
` + "```go" + `
result := {{.FunctionName}}("target.com"{{if .HasOptions}}, options{{end}})
fmt.Println(result.String())
` + "```" + `

### Plugin Usage
` + "```bash" + `
apex> use {{.ModuleName}}
apex> set target example.com
apex> run
` + "```" + `

{{if .HasOptions}}
## Options
- timeout: Operation timeout (default: 30s)
- Add your custom options here
{{end}}

## Output
The module returns a {{.StructName}}Result struct containing:
- Target information
- Scan results
- Execution time
- Timestamp

## Integration
This module integrates with the ApexPenetrateGo framework and can be used in:
- Manual testing
- Automated scans
- Custom workflows
- Reporting systems

## Notes
- Ensure you have permission to scan targets
- Follow responsible disclosure practices
- Consider rate limiting for external targets

## Generated
This module was generated on {{.Timestamp}} using ApexPenetrateGo module templates.
`

	tmpl := template.Must(template.New("documentation").Parse(docTemplate))

	templateData := mg.prepareTemplateData(config)
	templateData["Timestamp"] = time.Now().Format("2006-01-02 15:04:05")

	docPath := filepath.Join(filepath.Dir(config.OutputPath), "README_"+config.PackageName+".md")
	file, err := os.Create(docPath)
	if err != nil {
		return err
	}
	defer file.Close()

	return tmpl.Execute(file, templateData)
}

// generateExample generates an example usage file
func (mg *ModuleGenerator) generateExample(config ModuleTemplateConfig) error {
	exampleTemplate := `// Example usage of {{.ModuleName}} module
package main

import (
	"fmt"
	"apexPenetrateGo/internal/modules/{{.Category}}"
)

func main() {
	// Basic usage
	target := "example.com"
	{{if .HasOptions}}
	options := map[string]interface{}{
		"timeout": "30s",
		// Add your custom options here
	}
	result := {{.Category}}.{{.FunctionName}}(target, options)
	{{else}}
	result := {{.Category}}.{{.FunctionName}}(target)
	{{end}}

	// Print results
	fmt.Println(result.String())

	// Access specific result data
	if result.Success {
		fmt.Printf("Scan successful for %s\n", result.Target)
		fmt.Printf("Execution time: %s\n", result.ExecutionTime)
		{{if eq .Category "reconnaissance"}}
		fmt.Printf("Results found: %d\n", len(result.Results))
		{{else}}
		if result.Vulnerable {
			fmt.Printf("Vulnerabilities found: %d\n", len(result.Vulnerabilities))
		}
		{{end}}
	} else {
		fmt.Printf("Scan failed for %s\n", result.Target)
	}
}
`

	tmpl := template.Must(template.New("example").Parse(exampleTemplate))

	templateData := mg.prepareTemplateData(config)

	examplePath := filepath.Join(filepath.Dir(config.OutputPath), "example_"+config.PackageName+".go")
	file, err := os.Create(examplePath)
	if err != nil {
		return err
	}
	defer file.Close()

	return tmpl.Execute(file, templateData)
}

// GetModuleTemplateConfig creates a default configuration for a module type
func GetModuleTemplateConfig(templateType ModuleTemplateType, moduleName string) ModuleTemplateConfig {
	config := ModuleTemplateConfig{
		ModuleName:   moduleName,
		PackageName:  strings.ToLower(strings.ReplaceAll(moduleName, " ", "_")),
		Author:       "ApexPenetrate Developer",
		HasOptions:   true,
		HasHelp:      true,
		HasTests:     true,
		Dependencies: []string{},
		CustomFields: make(map[string]string),
	}

	switch templateType {
	case TemplateReconnaissance:
		config.Type = TemplateReconnaissance
		config.Category = "reconnaissance"
		config.Description = fmt.Sprintf("Performs %s reconnaissance", strings.ToLower(moduleName))
	case TemplateWebVulns:
		config.Type = TemplateWebVulns
		config.Category = "web"
		config.Description = fmt.Sprintf("Scans for %s vulnerabilities in web applications", strings.ToLower(moduleName))
	case TemplateNetworkVulns:
		config.Type = TemplateNetworkVulns
		config.Category = "network"
		config.Description = fmt.Sprintf("Scans for %s vulnerabilities in network services", strings.ToLower(moduleName))
	default:
		config.Type = TemplateCustom
		config.Category = "custom"
		config.Description = fmt.Sprintf("Custom %s module", strings.ToLower(moduleName))
	}

	return config
}
