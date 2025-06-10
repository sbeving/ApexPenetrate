// cmd/recon.go
package cmd

import (
	"apexPenetrateGo/internal/core"
	"apexPenetrateGo/internal/core/logger"
	"apexPenetrateGo/internal/modules/reconnaissance"
	"apexPenetrateGo/internal/modules/web_vulnerabilities"
	"apexPenetrateGo/internal/output"
	"apexPenetrateGo/internal/reporting"
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// Helper function for minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var (
	reconOutputPath   string
	reconOutputFormat string
	reconReverseIP    bool
	reconDirFuzz      bool
	reconGitHubDork   bool   // New flag for GitHub Dorking
	reconBreachCheck  bool   // New flag for Breach/Leak Check
	reconReportHTML   string // New flag for HTML report output path
	reconFullAuto     bool   // New flag for full-auto mode
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
		results := make(map[string]interface{}) // For report aggregation

		if reconFullAuto {
			color.Yellow("\n🚀 Running in FULL-AUTO mode! All enabled modules will be executed.")
			for _, plugin := range core.GetEnabledPlugins() {
				color.Cyan("\n▶️  Running module: %s", plugin.Name())
				res, err := plugin.Run(target, map[string]interface{}{})
				if err != nil {
					color.Red("❌ %s failed: %v", plugin.Name(), err)
				} else {
					results[plugin.Name()] = res
					if s, ok := res.(fmt.Stringer); ok {
						color.Green(s.String())
					} else {
						color.Green("%+v", res)
					}
				}
			} // Print summary table
			color.Magenta("\n📊 Summary Table:")
			for name, res := range results {
				emoji := "✅"
				if str, ok := res.(fmt.Stringer); ok && strings.Contains(strings.ToLower(str.String()), "fail") {
					emoji = "❌"
				}
				color.Cyan("%s %s", emoji, name)
			}
			if reconReportHTML != "" {
				reportGen := reporting.NewReportGenerator()
				reportGen.SetTarget(target)
				reportGen.FinalizeScan()
				err := reportGen.GenerateHTMLReport(reconReportHTML)
				if err != nil {
					color.Red("❌ Failed to generate HTML report: %v", err)
				} else {
					color.Magenta("\n📊 HTML report generated: %s", reconReportHTML)
				}
			}
			return
		}

		enumerator := reconnaissance.NewSubdomainEnumerator(target)
		subdomains, err := enumerator.EnumerateSubdomains()
		if err != nil {
			color.Red("❌ Subdomain enumeration failed: %v", err)
		} else if len(subdomains) == 0 {
			color.Yellow("⚠️  No subdomains found for %s", target)
		} else {
			color.Green("✅ Found %d subdomains!", len(subdomains))
		}
		results["subdomains"] = subdomains
		formattedOutput, err := output.FormatSubdomains(subdomains, target, reconOutputFormat)
		if err != nil {
			color.Red("❌ Output formatting failed: %v", err)
		}
		if reconOutputPath != "" {
			err = output.WriteOutput(reconOutputPath, formattedOutput)
			if err != nil {
				color.Red("❌ Failed to write output: %v", err)
			} else {
				color.Cyan("📄 Output saved to %s", reconOutputPath)
			}
		} else {
			color.Cyan("\n%s", formattedOutput)
		}

		// Reverse IP Lookup
		if reconReverseIP {
			rev, err := reconnaissance.ReverseIPLookup(target)
			if err != nil {
				color.Red("❌ Reverse IP lookup failed: %v", err)
			} else {
				color.Green("🌐 Reverse IP domains: %d found", len(rev.Domains))
				results["reverse_ip"] = rev
			}
		}

		// Directory/File Fuzzer
		if reconDirFuzz {
			fuzz := web_vulnerabilities.DirFuzzer(target, nil)
			color.Cyan(fuzz.String())
			results["dir_fuzz"] = fuzz
		}

		// GitHub Dorking
		if reconGitHubDork {
			dorker := reconnaissance.NewGitHubDorker(target, "")
			ctx := cmd.Context()
			dorkResults, err := dorker.Dork(ctx)
			if err != nil {
				color.Red("❌ GitHub dorking failed: %v", err)
			} else {
				reconnaissance.PrintGitHubDorkResults(dorkResults)
				results["github_dork"] = dorkResults
			}
		}

		// Breach/Leak Check
		if reconBreachCheck {
			breachRes, err := reconnaissance.HaveIBeenPwnedCheck(target)
			if err != nil {
				color.Red("❌ Breach check failed: %v", err)
			} else {
				reconnaissance.PrintBreachResults([]*reconnaissance.BreachResult{breachRes})
				results["breach_check"] = breachRes
			}
		} // HTML Report Generation
		if reconReportHTML != "" {
			reportGen := reporting.NewReportGenerator()
			reportGen.SetTarget(target)
			reportGen.FinalizeScan()
			err := reportGen.GenerateHTMLReport(reconReportHTML)
			if err != nil {
				color.Red("❌ Failed to generate HTML report: %v", err)
			} else {
				color.Magenta("\n📊 HTML report generated: %s", reconReportHTML)
			}
		}

		// Summary Table
		color.Cyan("\n================= SUMMARY =================")
		if subdomains, ok := results["subdomains"]; ok && subdomains != nil {
			color.Green("🌐 Subdomains: %d found", len(subdomains.([]string)))
		} else {
			color.Yellow("🌐 Subdomains: Not run or none found")
		}
		if rev, ok := results["reverse_ip"]; ok && rev != nil {
			color.Green("🔁 Reverse IP: %d domains", len(rev.(*reconnaissance.ReverseIPResult).Domains))
		}
		if fuzz, ok := results["dir_fuzz"]; ok && fuzz != nil {
			color.Green("🗂️ Dir Fuzz: %d found", len(fuzz.(*web_vulnerabilities.DirFuzzerResult).Found))
		}
		if dork, ok := results["github_dork"]; ok && dork != nil {
			color.Green("🐙 GitHub Dork: %d results", len(dork.([]reconnaissance.GitHubDorkResult)))
		}
		if breach, ok := results["breach_check"]; ok && breach != nil {
			br := breach.(*reconnaissance.BreachResult)
			if br.Found {
				color.Red("🛑 Breach Check: %s", br.Details)
			} else {
				color.Green("✅ Breach Check: %s", br.Details)
			}
		}
		color.Cyan("===========================================\n")

		log.Infof("Reconnaissance for %s completed.", target)
		color.Cyan("🎯 Recon complete for %s!", target)
	},
}

func init() {
	// Local flags for the recon command
	reconCmd.Flags().StringVarP(&reconOutputPath, "output", "o", "", "Output file path (optional)")
	reconCmd.Flags().StringVarP(&reconOutputFormat, "format", "f", "console", "Output format: console, json, txt, csv")
	reconCmd.Flags().BoolVar(&reconReverseIP, "reverseip", false, "Enable reverse IP lookup")
	reconCmd.Flags().BoolVar(&reconDirFuzz, "dirfuzz", false, "Enable directory/file fuzzing")
	reconCmd.Flags().BoolVar(&reconGitHubDork, "githubdork", false, "Enable GitHub dorking")
	reconCmd.Flags().BoolVar(&reconBreachCheck, "breachcheck", false, "Enable breach/leak check (HaveIBeenPwned)")
	reconCmd.Flags().StringVar(&reconReportHTML, "report-html", "", "Generate HTML report at specified path")
	reconCmd.Flags().BoolVar(&reconFullAuto, "full-auto", false, "Run all enabled modules and aggregate results")

	rootCmd.AddCommand(reconCmd)
}
