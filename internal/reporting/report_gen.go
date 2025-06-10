// internal/reporting/report_gen.go
package reporting

import (
	"apexPenetrateGo/internal/core/logger"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// ChartData represents data for Chart.js visualizations
type ChartData struct {
	Labels   []string  `json:"labels"`
	Datasets []Dataset `json:"datasets"`
}

// Dataset represents a dataset for Chart.js
type Dataset struct {
	Label           string    `json:"label"`
	Data            []float64 `json:"data"`
	BackgroundColor []string  `json:"backgroundColor"`
	BorderColor     []string  `json:"borderColor"`
	BorderWidth     int       `json:"borderWidth"`
}

// Vulnerability represents a security finding
type Vulnerability struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"` // HIGH, MEDIUM, LOW
	CVSS        float64   `json:"cvss"`
	Description string    `json:"description"`
	Impact      string    `json:"impact"`
	Remediation string    `json:"remediation"`
	Module      string    `json:"module"`
	Target      string    `json:"target"`
	Evidence    string    `json:"evidence"`
	Timestamp   time.Time `json:"timestamp"`
}

// ScanResult represents the overall scan results
type ScanResult struct {
	Target          string          `json:"target"`
	StartTime       time.Time       `json:"start_time"`
	EndTime         time.Time       `json:"end_time"`
	Duration        time.Duration   `json:"duration"`
	ModulesRun      []string        `json:"modules_run"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	RiskScore       float64         `json:"risk_score"`
	Statistics      ScanStats       `json:"statistics"`
}

// ScanStats provides statistical summary
type ScanStats struct {
	TotalVulns     int `json:"total_vulnerabilities"`
	HighSeverity   int `json:"high_severity"`
	MediumSeverity int `json:"medium_severity"`
	LowSeverity    int `json:"low_severity"`
	ModulesRun     int `json:"modules_run"`
}

// ReportGenerator handles generating various types of reports
type ReportGenerator struct {
	scanResult *ScanResult
	log        *logrus.Logger
}

// NewReportGenerator creates a new instance of ReportGenerator
func NewReportGenerator() *ReportGenerator {
	return &ReportGenerator{
		scanResult: &ScanResult{
			StartTime:       time.Now(),
			Vulnerabilities: []Vulnerability{},
			ModulesRun:      []string{},
		},
		log: logger.GetLogger(),
	}
}

// AddVulnerability adds a vulnerability to the scan results
func (r *ReportGenerator) AddVulnerability(vuln Vulnerability) {
	vuln.Timestamp = time.Now()
	if vuln.ID == "" {
		vuln.ID = fmt.Sprintf("APEX-%d", len(r.scanResult.Vulnerabilities)+1)
	}
	r.scanResult.Vulnerabilities = append(r.scanResult.Vulnerabilities, vuln)
}

// AddModuleRun records that a module was executed
func (r *ReportGenerator) AddModuleRun(moduleName string) {
	r.scanResult.ModulesRun = append(r.scanResult.ModulesRun, moduleName)
}

// SetTarget sets the scan target
func (r *ReportGenerator) SetTarget(target string) {
	r.scanResult.Target = target
}

// FinalizeScan completes the scan and calculates statistics
func (r *ReportGenerator) FinalizeScan() {
	r.scanResult.EndTime = time.Now()
	r.scanResult.Duration = r.scanResult.EndTime.Sub(r.scanResult.StartTime)
	r.calculateStatistics()
	r.calculateRiskScore()
}

// calculateStatistics computes scan statistics
func (r *ReportGenerator) calculateStatistics() {
	stats := &r.scanResult.Statistics
	stats.TotalVulns = len(r.scanResult.Vulnerabilities)
	stats.ModulesRun = len(r.scanResult.ModulesRun)

	for _, vuln := range r.scanResult.Vulnerabilities {
		switch vuln.Severity {
		case "HIGH":
			stats.HighSeverity++
		case "MEDIUM":
			stats.MediumSeverity++
		case "LOW":
			stats.LowSeverity++
		}
	}
}

// calculateRiskScore computes an overall risk score based on vulnerabilities
func (r *ReportGenerator) calculateRiskScore() {
	if len(r.scanResult.Vulnerabilities) == 0 {
		r.scanResult.RiskScore = 0
		return
	}

	totalScore := 0.0
	for _, vuln := range r.scanResult.Vulnerabilities {
		switch vuln.Severity {
		case "HIGH":
			totalScore += vuln.CVSS
		case "MEDIUM":
			totalScore += vuln.CVSS * 0.7
		case "LOW":
			totalScore += vuln.CVSS * 0.3
		}
	}

	// Normalize score to 0-100 range
	r.scanResult.RiskScore = (totalScore / float64(len(r.scanResult.Vulnerabilities))) * 10
	if r.scanResult.RiskScore > 100 {
		r.scanResult.RiskScore = 100
	}
}

// GenerateHTMLReport generates a comprehensive HTML report with interactive charts
func (r *ReportGenerator) GenerateHTMLReport(outputPath string) error {
	r.log.Infof("Generating enhanced HTML report with charts for target %s and saving to %s...", r.scanResult.Target, outputPath)

	// Sort vulnerabilities by severity
	sortedVulns := make([]Vulnerability, len(r.scanResult.Vulnerabilities))
	copy(sortedVulns, r.scanResult.Vulnerabilities)
	sort.Slice(sortedVulns, func(i, j int) bool {
		severityOrder := map[string]int{"HIGH": 3, "MEDIUM": 2, "LOW": 1}
		return severityOrder[sortedVulns[i].Severity] > severityOrder[sortedVulns[j].Severity]
	})

	htmlContent := r.generateEnhancedHTMLContent(sortedVulns)

	err := os.WriteFile(outputPath, []byte(htmlContent), 0644)
	if err != nil {
		r.log.Errorf("Failed to write HTML report to %s: %v", outputPath, err)
		return fmt.Errorf("failed to write HTML report: %w", err)
	}

	r.log.Info("Enhanced HTML report with interactive charts generated successfully.")
	return nil
}

// GenerateJSONReport generates a JSON report
func (r *ReportGenerator) GenerateJSONReport(outputPath string) error {
	r.log.Infof("Generating JSON report and saving to %s...", outputPath)

	jsonData, err := json.MarshalIndent(r.scanResult, "", "    ")
	if err != nil {
		r.log.Errorf("Failed to marshal scan results to JSON: %v", err)
		return fmt.Errorf("failed to generate JSON report: %w", err)
	}

	err = os.WriteFile(outputPath, jsonData, 0644)
	if err != nil {
		r.log.Errorf("Failed to write JSON report to %s: %v", outputPath, err)
		return fmt.Errorf("failed to write JSON report: %w", err)
	}

	r.log.Info("JSON report generated successfully.")
	return nil
}

func (r *ReportGenerator) generateHTMLContent(sortedVulns []Vulnerability) string {
	riskLevel := r.getRiskLevel()
	riskColor := r.getRiskColor()

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>ApexPenetrate Security Report</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background-color: #f5f5f5; 
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white; 
            padding: 30px; 
            border-radius: 10px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1); 
        }
        h1 { 
            color: #2c3e50; 
            border-bottom: 3px solid #3498db; 
            padding-bottom: 10px; 
        }
        .header-info { 
            display: grid; 
            grid-template-columns: 1fr 1fr; 
            gap: 20px; 
            margin: 20px 0; 
        }
        .risk-score { 
            background: %s; 
            color: white; 
            padding: 15px; 
            border-radius: 8px; 
            text-align: center; 
            font-size: 1.2em; 
            font-weight: bold; 
        }
        .stats-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 15px; 
            margin: 20px 0; 
        }
        .stat-card { 
            background: #f8f9fa; 
            padding: 15px; 
            border-radius: 8px; 
            text-align: center; 
            border-left: 4px solid #3498db; 
        }
        .stat-number { 
            font-size: 2em; 
            font-weight: bold; 
            color: #2c3e50; 
        }
        .vuln-card { 
            border: 1px solid #ddd; 
            border-radius: 8px; 
            margin: 15px 0; 
            overflow: hidden; 
        }
        .vuln-header { 
            padding: 15px; 
            color: white; 
            font-weight: bold; 
        }
        .severity-high { background: #e74c3c; }
        .severity-medium { background: #f39c12; }
        .severity-low { background: #27ae60; }
        .vuln-body { 
            padding: 15px; 
        }
        .timeline { 
            border-left: 3px solid #3498db; 
            padding-left: 20px; 
            margin: 20px 0; 
        }
        .timeline-item { 
            margin-bottom: 15px; 
            padding: 10px; 
            background: #f8f9fa; 
            border-radius: 5px; 
        }
        table { 
            width: 100%%; 
            border-collapse: collapse; 
            margin: 20px 0; 
        }
        th, td { 
            padding: 12px; 
            text-align: left; 
            border-bottom: 1px solid #ddd; 
        }
        th { 
            background-color: #3498db; 
            color: white; 
        }
        .module-list { 
            list-style-type: none; 
            padding: 0; 
        }
        .module-list li { 
            background: #ecf0f1; 
            margin: 5px 0; 
            padding: 8px 12px; 
            border-radius: 4px; 
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ ApexPenetrate Security Assessment Report</h1>
        
        <div class="header-info">
            <div>
                <h3>📊 Scan Information</h3>
                <p><strong>Target:</strong> %s</p>
                <p><strong>Start Time:</strong> %s</p>
                <p><strong>End Time:</strong> %s</p>
                <p><strong>Duration:</strong> %s</p>
                <p><strong>Modules Run:</strong> %d</p>
            </div>
            <div class="risk-score">
                <div>Overall Risk Score</div>
                <div style="font-size: 2em;">%.1f/100</div>
                <div>%s RISK</div>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">%d</div>
                <div>Total Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: #e74c3c;">%d</div>
                <div>High Severity</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: #f39c12;">%d</div>
                <div>Medium Severity</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: #27ae60;">%d</div>
                <div>Low Severity</div>
            </div>
        </div>

        %s

        %s

        %s

        <div style="margin-top: 40px; padding: 20px; background: #ecf0f1; border-radius: 8px; text-align: center; color: #7f8c8d;">
            <p>Report generated by ApexPenetrate on %s</p>
            <p>This report contains sensitive security information and should be handled accordingly.</p>
        </div>
    </div>
</body>
</html>`,
		riskColor,
		r.scanResult.Target,
		r.scanResult.StartTime.Format("2006-01-02 15:04:05 MST"),
		r.scanResult.EndTime.Format("2006-01-02 15:04:05 MST"),
		r.scanResult.Duration.String(),
		len(r.scanResult.ModulesRun),
		r.scanResult.RiskScore,
		riskLevel,
		r.scanResult.Statistics.TotalVulns,
		r.scanResult.Statistics.HighSeverity,
		r.scanResult.Statistics.MediumSeverity,
		r.scanResult.Statistics.LowSeverity,
		r.generateVulnerabilitiesSection(sortedVulns),
		r.generateTimelineSection(),
		r.generateModulesSection(),
		time.Now().Format("2006-01-02 15:04:05 MST"),
	)
}

func (r *ReportGenerator) getRiskLevel() string {
	if r.scanResult.RiskScore >= 80 {
		return "CRITICAL"
	} else if r.scanResult.RiskScore >= 60 {
		return "HIGH"
	} else if r.scanResult.RiskScore >= 40 {
		return "MEDIUM"
	} else if r.scanResult.RiskScore >= 20 {
		return "LOW"
	}
	return "MINIMAL"
}

func (r *ReportGenerator) getRiskColor() string {
	if r.scanResult.RiskScore >= 80 {
		return "#8e44ad" // Purple for critical
	} else if r.scanResult.RiskScore >= 60 {
		return "#e74c3c" // Red for high
	} else if r.scanResult.RiskScore >= 40 {
		return "#f39c12" // Orange for medium
	} else if r.scanResult.RiskScore >= 20 {
		return "#f1c40f" // Yellow for low
	}
	return "#27ae60" // Green for minimal
}

func (r *ReportGenerator) generateVulnerabilitiesSection(vulns []Vulnerability) string {
	if len(vulns) == 0 {
		return "<h2>🔍 Vulnerabilities</h2><p>No vulnerabilities found during this scan.</p>"
	}

	content := "<h2>🔍 Vulnerabilities Found</h2>\n"

	for _, vuln := range vulns {
		severityClass := fmt.Sprintf("severity-%s", strings.ToLower(vuln.Severity))
		content += fmt.Sprintf(`
        <div class="vuln-card">
            <div class="vuln-header %s">
                %s - %s
            </div>
            <div class="vuln-body">
                <p><strong>🎯 Target:</strong> %s</p>
                <p><strong>📊 CVSS Score:</strong> %.1f</p>
                <p><strong>🔍 Module:</strong> %s</p>
                <p><strong>📝 Description:</strong> %s</p>
                <p><strong>💥 Impact:</strong> %s</p>
                <p><strong>🔧 Remediation:</strong> %s</p>
                <p><strong>🔬 Evidence:</strong> <code>%s</code></p>
                <p><strong>⏰ Discovered:</strong> %s</p>
            </div>
        </div>`,
			severityClass,
			vuln.Severity,
			vuln.Title,
			vuln.Target,
			vuln.CVSS,
			vuln.Module,
			vuln.Description,
			vuln.Impact,
			vuln.Remediation,
			vuln.Evidence,
			vuln.Timestamp.Format("2006-01-02 15:04:05"),
		)
	}

	return content
}

func (r *ReportGenerator) generateTimelineSection() string {
	content := "<h2>⏱️ Scan Timeline</h2>\n"
	if len(r.scanResult.Vulnerabilities) == 0 {
		content += "<p>No timeline events to display.</p>"
		return content
	}

	content += "<div class=\"timeline\">\n"

	// Add scan start
	content += fmt.Sprintf(`
        <div class="timeline-item">
            <strong>%s</strong> - Scan started on %s
        </div>`,
		r.scanResult.StartTime.Format("15:04:05"),
		r.scanResult.Target,
	)

	// Add vulnerabilities
	for _, vuln := range r.scanResult.Vulnerabilities {
		content += fmt.Sprintf(`
        <div class="timeline-item">
            <strong>%s</strong> - %s vulnerability found: %s
        </div>`,
			vuln.Timestamp.Format("15:04:05"),
			vuln.Severity,
			vuln.Title,
		)
	}

	// Add scan completion
	content += fmt.Sprintf(`
        <div class="timeline-item">
            <strong>%s</strong> - Scan completed (Duration: %s)
        </div>`,
		r.scanResult.EndTime.Format("15:04:05"),
		r.scanResult.Duration.String(),
	)

	content += "</div>\n"
	return content
}

func (r *ReportGenerator) generateModulesSection() string {
	content := "<h2>🔧 Modules Executed</h2>\n"
	if len(r.scanResult.ModulesRun) == 0 {
		content += "<p>No modules were executed during this scan.</p>"
		return content
	}

	content += "<ul class=\"module-list\">\n"
	for _, module := range r.scanResult.ModulesRun {
		content += fmt.Sprintf("    <li>%s</li>\n", module)
	}
	content += "</ul>\n"

	return content
}
