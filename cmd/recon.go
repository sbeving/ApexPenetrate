// cmd/recon.go
package cmd

import (
	"apexPenetrateGo/internal/core/logger"
	"apexPenetrateGo/internal/modules/reconnaissance"
	"apexPenetrateGo/internal/output"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	reconWordlistPath string
	reconOutputPath   string
	reconOutputFormat string
)

// reconCmd represents the recon command
var reconCmd = &cobra.Command{
	Use:   "recon [target]",
	Short: "Performs reconnaissance on the TARGET, including subdomain enumeration.",
	Long: `The recon command automates the initial information gathering phase of a
penetration test. It can enumerate subdomains using brute-force and passive
techniques, and save results in various formats.`,
	Example: `  apexpenetrate recon example.com
  apexpenetrate recon example.com --wordlist custom_subs.txt -o results.json -f json
  apexpenetrate recon example.com -v`,
	Args: cobra.ExactArgs(1), // Requires exactly one argument (target)
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		log := logger.GetLogger()

		log.Infof("Starting reconnaissance for target: %s", target)

		enumerator := reconnaissance.NewSubdomainEnumerator(target, reconWordlistPath)
		subdomains, err := enumerator.EnumerateSubdomains()
		if err != nil {
			log.Errorf("Error during subdomain enumeration: %v", err)
			os.Exit(1)
		}

		if len(subdomains) == 0 {
			log.Warnf("No subdomains found for %s.", target)
			return
		}

		formattedOutput, err := output.FormatSubdomains(subdomains, target, reconOutputFormat)
		if err != nil {
			log.Errorf("Error formatting output: %v", err)
			os.Exit(1)
		}

		if reconOutputPath != "" {
			err = output.WriteOutput(reconOutputPath, formattedOutput)
			if err != nil {
				log.Errorf("Error saving results to %s: %v", reconOutputPath, err)
				os.Exit(1)
			}
			log.Infof("Results saved to %s in %s format.", reconOutputPath, reconOutputFormat)
		} else {
			if reconOutputFormat == "console" {
				fmt.Println(formattedOutput)
			} else {
				log.Info("Output format specified but no output file provided. Printing to console.")
				fmt.Println(formattedOutput)
			}
		}

		log.Infof("Reconnaissance for %s completed.", target)
	},
}

func init() {
	rootCmd.AddCommand(reconCmd)

	// Local flags for the recon command
	reconCmd.Flags().StringVarP(&reconWordlistPath, "wordlist", "w", "", "Path to a custom wordlist for subdomain enumeration.")
	reconCmd.Flags().StringVarP(&reconOutputPath, "output", "o", "", "Output file to save results.")
	reconCmd.Flags().StringVarP(&reconOutputFormat, "format", "f", "console", "Output format (json, txt, csv, console).")
	reconCmd.MarkFlagFilename("wordlist") // Suggests wordlist is a file path
	reconCmd.MarkFlagFilename("output")   // Suggests output is a file path
}
