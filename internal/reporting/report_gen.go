// internal/reporting/report_gen.go
package reporting

import (
	"apexPenetrateGo/internal/core/logger"
	"encoding/json" // Use json for simple data display in HTML
	"fmt"
	"os"
	"time"
)

// ReportGenerator handles generating various types of reports
type ReportGenerator struct {
	results map[string]interface{} // Generic map for results
	log     *logrus.Logger
}

// NewReportGenerator creates a new instance of ReportGenerator
func NewReportGenerator(results map[string]interface{}) *ReportGenerator {
	return &ReportGenerator{
		results: results,
		log:     logger.GetLogger(),
	}
}

// GenerateHTMLReport simulates generating an HTML report.
func (r *ReportGenerator) GenerateHTMLReport(outputPath string) error {
	r.log.Infof("Generating HTML report for results and saving to %s...", outputPath)

	// Marshal results to JSON for display in the HTML
	resultsJSON, err := json.MarshalIndent(r.results, "", "    ")
	if err != nil {
		r.log.Errorf("Failed to marshal results to JSON for HTML report: %v", err)
		return fmt.Errorf("failed to prepare report data: %w", err)
	}

	htmlContent := fmt.Sprintf(<!DOCTYPE html>
<html>
<head>
    <title>ApexPenetrate Report</title>
    <style>
        body { font-family: sans-serif; margin: 20px; }
        h1 { color: #333; }
        pre { background-color: #eee; padding: 10px; border-radius: 5px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>ApexPenetrate Automated Report</h1>
    <p>Report generated on: %s</p>
    <h2>Results Summary</h2>
    <pre>%s</pre>
    <p>This is a placeholder report. Implement detailed formatting here.</p>
</body>
</html>, time.Now().Format("2006-01-02 15:04:05 MST"), string(resultsJSON))

	err = os.WriteFile(outputPath, []byte(htmlContent), 0644) // 0644 is standard file permissions
	if err != nil {
		r.log.Errorf("Failed to write HTML report to %s: %v", outputPath, err)
		return fmt.Errorf("failed to write HTML report: %w", err)
	}

	r.log.Info("HTML report generated successfully.")
	return nil
}
