// internal/output/formatter.go
package output

import (
	"apexPenetrateGo/internal/core"
	"apexPenetrateGo/internal/core/logger"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// FormatSubdomains formats a list of subdomains into the specified format.
func FormatSubdomains(subdomains []string, target string, outputFormat string) (string, error) {
	log := logger.GetLogger()
	switch outputFormat {
	case "json":
		data := map[string]interface{}{
			"target":     target,
			"subdomains": subdomains,
		}
		jsonData, err := json.MarshalIndent(data, "", "    ")
		if err != nil {
			return "", fmt.Errorf("failed to marshal JSON: %w", err)
		}
		return string(jsonData), nil
	case "txt":
		return strings.Join(subdomains, "\r\n"), nil
	case "csv":
		var b strings.Builder
		writer := csv.NewWriter(&b)
		if err := writer.Write([]string{"subdomain"}); err != nil { // CSV header
			return "", fmt.Errorf("failed to write CSV header: %w", err)
		}
		for _, sub := range subdomains {
			if err := writer.Write([]string{sub}); err != nil {
				return "", fmt.Errorf("failed to write subdomain to CSV: %w", err)
			}
		}
		writer.Flush()
		return b.String(), nil
	case "console":
		if len(subdomains) > 0 {
			header := fmt.Sprintf(`
--- Found Subdomains for %s ---
`, target)
			return header + strings.Join(subdomains, "\r\n") + "\r\n------------------------------------", nil
		}
		return fmt.Sprintf("No subdomains found for %s.", target), nil
	default:
		log.Errorf("Unsupported output format: %s", outputFormat)
		return "", core.ErrOutputFormat
	}
}

// WriteOutput writes content to a specified file.
func WriteOutput(filepath string, content string) error {
	log := logger.GetLogger()
	err := os.WriteFile(filepath, []byte(content), 0644) // 0644 is standard file permissions
	if err != nil {
		log.Errorf("Failed to write output to %s: %v", filepath, err)
		return core.ErrFileWrite
	}
	return nil
}
