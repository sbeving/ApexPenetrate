// internal/reporting/enhanced_report.go
package reporting

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// generateEnhancedHTMLContent generates HTML content with Chart.js interactive charts
func (r *ReportGenerator) generateEnhancedHTMLContent(sortedVulns []Vulnerability) string {
	riskLevel := r.getRiskLevel()
	riskColor := r.getRiskColor()

	// Generate chart data
	chartData := r.generateChartData()
	chartDataJSON, _ := json.Marshal(chartData)

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>ApexPenetrate Security Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
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
        .charts-section {
            margin: 30px 0;
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        .chart-container {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #dee2e6;
        }
        .chart-title {
            font-weight: bold;
            margin-bottom: 15px;
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
            cursor: pointer;
            user-select: none;
        }
        .severity-high { background: #e74c3c; }
        .severity-medium { background: #f39c12; }
        .severity-low { background: #27ae60; }
        .vuln-body { 
            padding: 15px; 
            display: none;
        }
        .vuln-body.expanded {
            display: block;
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

        <div class="charts-section">
            <div class="chart-container">
                <div class="chart-title">📊 Vulnerability Distribution</div>
                <canvas id="severityChart" width="400" height="200"></canvas>
            </div>
            <div class="chart-container">
                <div class="chart-title">📈 Risk Timeline</div>
                <canvas id="timelineChart" width="400" height="200"></canvas>
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

    <script>
        // Initialize charts
        const chartData = %s;
        
        // Severity Chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {
            type: 'doughnut',
            data: {
                labels: ['High', 'Medium', 'Low'],
                datasets: [{
                    data: [%d, %d, %d],
                    backgroundColor: ['#e74c3c', '#f39c12', '#27ae60'],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });

        // Timeline Chart
        const timelineCtx = document.getElementById('timelineChart').getContext('2d');
        new Chart(timelineCtx, {
            type: 'line',
            data: {
                labels: chartData.timeline.labels,
                datasets: [{
                    label: 'Risk Level Over Time',
                    data: chartData.timeline.data,
                    backgroundColor: 'rgba(52, 152, 219, 0.2)',
                    borderColor: '#3498db',
                    borderWidth: 2,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });

        // Collapsible vulnerability cards
        document.querySelectorAll('.vuln-header').forEach(header => {
            header.addEventListener('click', function() {
                const body = this.nextElementSibling;
                body.classList.toggle('expanded');
                
                // Update arrow indicator
                const text = this.textContent;
                if (body.classList.contains('expanded')) {
                    this.textContent = text.replace('▶', '▼');
                } else {
                    this.textContent = text.replace('▼', '▶');
                }
            });
        });
    </script>
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
		r.generateEnhancedVulnerabilitiesSection(sortedVulns),
		r.generateTimelineSection(),
		r.generateModulesSection(),
		time.Now().Format("2006-01-02 15:04:05 MST"),
		string(chartDataJSON),
		r.scanResult.Statistics.HighSeverity,
		r.scanResult.Statistics.MediumSeverity,
		r.scanResult.Statistics.LowSeverity,
	)
}

// generateChartData creates data structures for Chart.js visualizations
func (r *ReportGenerator) generateChartData() map[string]interface{} {
	// Create timeline data based on vulnerability discovery times
	timelineLabels := []string{}
	timelineData := []float64{}
	if len(r.scanResult.Vulnerabilities) > 0 {
		// Group vulnerabilities by time intervals
		startTime := r.scanResult.StartTime

		for i := 0; i < 10; i++ { // 10 time intervals
			timePoint := startTime.Add(time.Duration(i) * r.scanResult.Duration / 10)
			timeLabel := timePoint.Format("15:04")
			timelineLabels = append(timelineLabels, timeLabel)

			// Calculate cumulative risk at this time point
			riskAtTime := 0.0
			for _, vuln := range r.scanResult.Vulnerabilities {
				if vuln.Timestamp.Before(timePoint) || vuln.Timestamp.Equal(timePoint) {
					switch vuln.Severity {
					case "HIGH":
						riskAtTime += 10
					case "MEDIUM":
						riskAtTime += 5
					case "LOW":
						riskAtTime += 1
					}
				}
			}
			timelineData = append(timelineData, riskAtTime)
		}
	} else {
		// Default data if no vulnerabilities
		timelineLabels = []string{"Start", "End"}
		timelineData = []float64{0, 0}
	}

	return map[string]interface{}{
		"timeline": map[string]interface{}{
			"labels": timelineLabels,
			"data":   timelineData,
		},
	}
}

// generateEnhancedVulnerabilitiesSection creates collapsible vulnerability cards
func (r *ReportGenerator) generateEnhancedVulnerabilitiesSection(vulns []Vulnerability) string {
	if len(vulns) == 0 {
		return "<h2>🔍 Vulnerabilities</h2><p>No vulnerabilities found during this scan.</p>"
	}

	content := "<h2>🔍 Vulnerabilities Found</h2>\n"

	for _, vuln := range vulns {
		severityClass := fmt.Sprintf("severity-%s", strings.ToLower(vuln.Severity))
		content += fmt.Sprintf(`
        <div class="vuln-card">
            <div class="vuln-header %s">
                %s - %s ▶
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
