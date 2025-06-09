// cmd/root.go
package cmd

import (
	"apexPenetrateGo/internal/core"
	"apexPenetrateGo/internal/core/logger" // Import the logger
	"apexPenetrateGo/internal/modules/network_vulnerabilities"
	"apexPenetrateGo/internal/modules/reconnaissance"
	"apexPenetrateGo/internal/modules/web_vulnerabilities"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	verbose      bool
	version      = "0.1.0" // Define tool version here
	shodanAPIKey string
	censysID     string
	censysSecret string
	modules      string // comma-separated list for --modules
	configPath   string
	config       *core.Config
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "apexpenetrate",
	Short: "ApexPenetrate: Your ultimate automated penetration testing tool.",
	Long: `ApexPenetrate is an automated penetration testing tool designed to streamline
various stages of security assessments, from reconnaissance to vulnerability
scanning and reporting. Built with Go, it aims to be performant, modular, and
easy to use, providing valuable insights for security professionals worldwide.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Initialize logger before any command runs
		if verbose {
			logger.SetupLogger("debug")
		} else {
			logger.SetupLogger("info")
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\r\n", err)
		os.Exit(1)
	}
}

var (
	autoTarget  string
	autoTimeout time.Duration
)

var autoCmd = &cobra.Command{
	Use:   "full-auto",
	Short: "Run a full automated penetration test workflow on a target.",
	Long:  `Performs subdomain enumeration, port scanning, service detection, SMB enum, and generates a report.`,
	Run: func(cmd *cobra.Command, args []string) {
		if autoTarget == "" {
			fmt.Fprintln(os.Stderr, "--target is required")
			os.Exit(1)
		}
		log := logger.GetLogger()
		log.Infof("[AUTO] Starting full automated workflow for %s", autoTarget)

		// Parse modules to run
		mods := map[string]bool{}
		for _, m := range strings.Split(modules, ",") {
			mods[strings.TrimSpace(strings.ToLower(m))] = true
		}
		all := mods["all"]

		// 1. Subdomain Enumeration
		var subdomains []string
		if all || mods["recon"] {
			log.Info("[AUTO] Running subdomain enumeration...")
			enumerator := reconnaissance.NewSubdomainEnumerator(autoTarget, "")
			subdomains, _ = enumerator.EnumerateSubdomains()
			log.Infof("[AUTO] Found %d subdomains", len(subdomains))
		}

		// 2. Port Scan + Banner Grabbing
		var portResults map[int]map[string]string
		if all || mods["ports"] {
			log.Info("[AUTO] Running port scan with banner grabbing...")
			scanner := reconnaissance.NewPortScanner(autoTarget, nil, autoTimeout)
			portResults = scanner.ScanPortsWithBanners()
		}

		// 3. Shodan Lookup
		if (all || mods["shodan"]) && shodanAPIKey != "" {
			log.Info("[AUTO] Querying Shodan API...")
			shodanRes, err := reconnaissance.ShodanHostLookup(shodanAPIKey, autoTarget)
			if err == nil {
				fmt.Printf("Shodan: IP: %s, Ports: %v, Hostnames: %v\n", shodanRes.IPStr, shodanRes.Ports, shodanRes.Hostnames)
			} else {
				log.Warnf("Shodan error: %v", err)
			}
		}

		// 4. Censys Lookup
		if (all || mods["censys"]) && censysID != "" && censysSecret != "" {
			log.Info("[AUTO] Querying Censys API...")
			censysRes, err := reconnaissance.CensysHostLookup(censysID, censysSecret, autoTarget)
			if err == nil {
				fmt.Printf("Censys: IP: %s, Protocols: %v, Location: %s, %s\n", censysRes.IP, censysRes.Protocols, censysRes.Location.City, censysRes.Location.Country)
			} else {
				log.Warnf("Censys error: %v", err)
			}
		}

		// 5. XSS Scan (on all subdomains if found)
		if (all || mods["xss"]) && len(subdomains) > 0 {
			log.Info("[AUTO] Running XSS scan on discovered subdomains...")
			for _, sub := range subdomains {
				url := "http://" + sub
				xssScanner := web_vulnerabilities.NewXSSScanner(url)
				findings := xssScanner.ScanXSS()
				for _, f := range findings {
					fmt.Printf("XSS found: %v\n", f)
				}
			}
		}

		// 5b. SQLi Scan (on all subdomains if found)
		if (all || mods["sqli"]) && len(subdomains) > 0 {
			log.Info("[AUTO] Running SQLi scan on discovered subdomains...")
			for _, sub := range subdomains {
				url := "http://" + sub
				sqliScanner := web_vulnerabilities.NewSQLiScanner(url)
				findings := sqliScanner.ScanSQLi()
				for _, f := range findings {
					fmt.Printf("SQLi found: %v\n", f)
				}
			}
		}

		// 5c. DNS Recon
		if (all || mods["dns"]) {
			log.Info("[AUTO] Running DNS recon...")
			dnsRes, err := reconnaissance.DNSRecon(autoTarget)
			if err == nil {
				fmt.Printf("DNS Records: %v\n", dnsRes.Records)
			} else {
				log.Warnf("DNS recon error: %v", err)
			}
		}

		// 5d. HTTP Recon
		if (all || mods["http"]) {
			log.Info("[AUTO] Running HTTP recon...")
			httpRes, err := reconnaissance.HTTPRecon("http://" + autoTarget)
			if err == nil {
				fmt.Printf("HTTP Status: %d, Headers: %v\n", httpRes.Status, httpRes.Headers)
			} else {
				log.Warnf("HTTP recon error: %v", err)
			}
		}

		// 6. SMB Enum if 445 open
		var smbResults []map[string]string
		if (all || mods["smb"]) && portResults != nil {
			if port, ok := portResults[445]; ok && port["state"] == "OPEN" {
				log.Info("[AUTO] Running SMB enumeration...")
				smbEnum := network_vulnerabilities.NewSMBEnumerator(autoTarget)
				smbResults = smbEnum.EnumerateShares()
			}
		}

		// 7. Generate Report (console summary for now)
		fmt.Println("\n--- Automated Recon Summary ---")
		if len(subdomains) > 0 {
			fmt.Printf("Subdomains found: %d\n", len(subdomains))
		}
		if portResults != nil {
			fmt.Printf("Open ports: ")
			for port, res := range portResults {
				if res["state"] == "OPEN" {
					fmt.Printf("%d (banner: %s), ", port, strings.TrimSpace(res["banner"]))
				}
			}
			fmt.Println()
		}
		if len(smbResults) > 0 {
			fmt.Println("SMB Shares:")
			for _, share := range smbResults {
				fmt.Printf("- %s (%s)\n", share["share"], share["access"])
			}
		}
		fmt.Println("--- End of Summary ---")
	},
}

func loadConfigOrExit() {
	if configPath != "" {
		cfg, err := core.LoadConfig(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
			os.Exit(1)
		}
		config = cfg
		if shodanAPIKey == "" && cfg.ShodanAPIKey != "" {
			shodanAPIKey = cfg.ShodanAPIKey
		}
		if censysID == "" && cfg.CensysID != "" {
			censysID = cfg.CensysID
		}
		if censysSecret == "" && cfg.CensysSecret != "" {
			censysSecret = cfg.CensysSecret
		}
		if modules == "all" && len(cfg.Modules) > 0 {
			modules = strings.Join(cfg.Modules, ",")
		}
	}
}

func init() {
	// Add global flags here
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output for debugging.")
	rootCmd.PersistentFlags().StringVar(&shodanAPIKey, "shodan", os.Getenv("SHODAN_API_KEY"), "Shodan API key (or set SHODAN_API_KEY env)")
	rootCmd.PersistentFlags().StringVar(&censysID, "censys-id", os.Getenv("CENSYS_API_ID"), "Censys API ID (or set CENSYS_API_ID env)")
	rootCmd.PersistentFlags().StringVar(&censysSecret, "censys-secret", os.Getenv("CENSYS_API_SECRET"), "Censys API Secret (or set CENSYS_API_SECRET env)")
	rootCmd.PersistentFlags().StringVar(&modules, "modules", "all", "Comma-separated list of modules to run (all, or e.g. recon,ports,shodan,xss)")
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "Path to config file (YAML or JSON)")

	// Add the version flag if you want it distinct from the default Cobra version
	rootCmd.Version = version
	rootCmd.SetVersionTemplate("{{.Version}}\r\n")

	cobra.OnInitialize(loadConfigOrExit)

	rootCmd.AddCommand(autoCmd)
	autoCmd.Flags().StringVarP(&autoTarget, "target", "t", "", "Target domain or IP (required)")
	autoCmd.Flags().DurationVarP(&autoTimeout, "timeout", "w", 2*time.Second, "Timeout per port (e.g. 1s, 500ms)")
	autoCmd.MarkFlagRequired("target")
}
