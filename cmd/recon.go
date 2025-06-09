// cmd/recon.go
package cmd

import (
	"apexPenetrateGo/internal/core/logger"
	"apexPenetrateGo/internal/modules/reconnaissance"
	"apexPenetrateGo/internal/output"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	reconOutputPath   string
	reconOutputFormat string
)

// reconCmd represents the recon command
var reconCmd = &cobra.Command{
	Use:   "recon [target]",
	Short: "Performs reconnaissance on the TARGET, including subdomain enumeration.",
	Long: `The recon command automates the initial information gathering phase of a
penetration test. It can enumerate subdomains using DNS and OSINT
techniques, and save results in various formats.`,
	Example: `  apexpenetrate recon example.com
  apexpenetrate recon example.com -o results.json -f json
  apexpenetrate recon example.com -v`,
	Args: cobra.ExactArgs(1), // Requires exactly one argument (target)
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		log := logger.GetLogger()
		color.Cyan("\n🔎 Starting Recon for %s...", target)

		log.Infof("Starting reconnaissance for target: %s", target)
		enumerator := reconnaissance.NewSubdomainEnumerator(target)
		subdomains, err := enumerator.EnumerateSubdomains()
		if err != nil {
			color.Red("❌ Subdomain enumeration failed: %v", err)
			os.Exit(1)
		}
		if len(subdomains) == 0 {
			color.Yellow("⚠️  No subdomains found for %s.", target)
		} else {
			color.Green("🎯 Found %d subdomains for %s!", len(subdomains), target)
		}
		formattedOutput, err := output.FormatSubdomains(subdomains, target, reconOutputFormat)
		if err != nil {
			color.Red("❌ Output formatting failed: %v", err)
			os.Exit(1)
		}
		if reconOutputPath != "" {
			err = output.WriteOutput(reconOutputPath, formattedOutput)
			if err != nil {
				color.Red("❌ Failed to write output: %v", err)
				os.Exit(1)
			}
			color.Cyan("📄 Results saved to %s", reconOutputPath)
		} else {
			color.Cyan("\n%s", formattedOutput)
		}
		log.Infof("Reconnaissance for %s completed.", target)
		color.Cyan("🎯 Recon complete for %s!", target)
	},
}

func init() {
	rootCmd.AddCommand(reconCmd)

	// Local flags for the recon command
	reconCmd.Flags().StringVarP(&reconOutputPath, "output", "o", "", "Output file to save results.")
	reconCmd.Flags().StringVarP(&reconOutputFormat, "format", "f", "console", "Output format: console, json, txt, csv.")
}
