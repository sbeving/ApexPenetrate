// cmd/scan.go
package cmd

import (
	"apexPenetrateGo/internal/modules/reconnaissance"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	scanTarget  string
	scanPorts   string // e.g. "22,80,443" or "1-1024"
	scanTimeout time.Duration
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan TCP ports on a target host.",
	Long:  `Scan TCP ports on a target host. Supports single ports, comma-separated lists, or ranges (e.g. 1-1024).`,
	Run: func(cmd *cobra.Command, args []string) {
		if scanTarget == "" {
			color.Red("❌ --target is required")
			os.Exit(1)
		}
		var ports []int
		if strings.Contains(scanPorts, "-") {
			parts := strings.SplitN(scanPorts, "-", 2)
			if len(parts) != 2 {
				color.Red("❌ Invalid port range format. Use start-end, e.g. 1-1024")
				os.Exit(1)
			}
			var start, end int
			fmt.Sscanf(parts[0], "%d", &start)
			fmt.Sscanf(parts[1], "%d", &end)
			ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
			defer cancel()
			scanner := reconnaissance.NewPortScanner(scanTarget, nil, scanTimeout)
			results := scanner.ScanPortRange(ctx, start, end)
			printScanResultsColor(results)
			return
		}
		// Comma-separated or single port
		for _, p := range strings.Split(scanPorts, ",") {
			var port int
			fmt.Sscanf(strings.TrimSpace(p), "%d", &port)
			if port > 0 {
				ports = append(ports, port)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
		defer cancel()
		scanner := reconnaissance.NewPortScanner(scanTarget, ports, scanTimeout)
		results := scanner.ScanPortsCtx(ctx)
		printScanResultsColor(results)
	},
}

func printScanResultsColor(results map[int]string) {
	open, closed, cancelled := 0, 0, 0
	for port, state := range results {
		if state == "OPEN" {
			color.Green("✅ Port %d: %s", port, state)
			open++
		} else if state == "CLOSED" {
			color.Red("❌ Port %d: %s", port, state)
			closed++
		} else if state == "CANCELLED" {
			color.Yellow("⚠️  Port %d: %s", port, state)
			cancelled++
		}
	}
	color.Cyan("\nSummary: %d open, %d closed, %d cancelled\n", open, closed, cancelled)
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringVarP(&scanTarget, "target", "t", "", "Target IP or hostname (required)")
	scanCmd.Flags().StringVarP(&scanPorts, "ports", "p", "1-1024", "Ports to scan (e.g. 22,80,443 or 1-1024)")
	scanCmd.Flags().DurationVarP(&scanTimeout, "timeout", "w", 2*time.Second, "Timeout per port (e.g. 1s, 500ms)")
	scanCmd.MarkFlagRequired("target")
}
