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

	"github.com/fatih/color"
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
	printBanner()
	if err := rootCmd.Execute(); err != nil {
		color.Red("Error: %v", err)
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
		color.Cyan("\n🚀 Starting ApexPenetrate Full-Auto Workflow for %s! 🚀\n", autoTarget)

		// Parse modules to run
		mods := map[string]bool{}
		for _, m := range strings.Split(modules, ",") {
			mods[strings.TrimSpace(strings.ToLower(m))] = true
		}
		all := mods["all"]

		// 1. Subdomain Enumeration
		var subdomains []string
		if all || mods["recon"] {
			color.Yellow("🔎 Running subdomain enumeration...")
			enumerator := reconnaissance.NewSubdomainEnumerator(autoTarget)
			subdomains, _ = enumerator.EnumerateSubdomains()
			color.Green("✅ Found %d subdomains", len(subdomains))
		}

		// 2. Port Scan + Banner Grabbing
		var portResults map[int]map[string]string
		var smbResults []map[string]string
		if all || mods["ports"] {
			color.Yellow("🔌 Running port scan with banner grabbing...")
			scanner := reconnaissance.NewPortScanner(autoTarget, nil, autoTimeout)
			portResults = scanner.ScanPortsWithBanners()
			color.Green("✅ Port scan complete!")
		}

		// 3. Shodan Lookup
		if (all || mods["shodan"]) && shodanAPIKey != "" {
			color.Yellow("🌐 Querying Shodan API...")
			shodanRes, err := reconnaissance.ShodanHostLookup(shodanAPIKey, autoTarget)
			if err == nil {
				color.Green("✅ Shodan: IP: %s, Ports: %v, Hostnames: %v", shodanRes.IPStr, shodanRes.Ports, shodanRes.Hostnames)
			} else {
				color.Red("❌ Shodan error: %v", err)
			}
		}

		// 4. Censys Lookup
		if (all || mods["censys"]) && censysID != "" && censysSecret != "" {
			color.Yellow("🌐 Querying Censys API...")
			censysRes, err := reconnaissance.CensysHostLookup(censysID, censysSecret, autoTarget)
			if err == nil {
				color.Green("✅ Censys: IP: %s, Protocols: %v, Location: %s, %s", censysRes.IP, censysRes.Protocols, censysRes.Location.City, censysRes.Location.Country)
			} else {
				color.Red("❌ Censys error: %v", err)
			}
		}

		// 5. XSS Scan (on all subdomains if found)
		if (all || mods["xss"]) && len(subdomains) > 0 {
			color.Yellow("🧪 Running XSS scan on discovered subdomains...")
			for _, sub := range subdomains {
				url := "http://" + sub
				xssScanner := web_vulnerabilities.NewXSSScanner(url)
				findings := xssScanner.ScanXSS()
				for _, f := range findings {
					color.Red("🚨 XSS found: %v", f)
				}
			}
		}

		// 5b. SQLi Scan (on all subdomains if found)
		if (all || mods["sqli"]) && len(subdomains) > 0 {
			color.Yellow("🧪 Running SQLi scan on discovered subdomains...")
			for _, sub := range subdomains {
				url := "http://" + sub
				sqliScanner := web_vulnerabilities.NewSQLiScanner(url)
				findings := sqliScanner.ScanSQLi()
				for _, f := range findings {
					color.Red("🚨 SQLi found: %v", f)
				}
			}
		}

		// 5c. DNS Recon
		if all || mods["dns"] {
			color.Yellow("🌐 Running DNS recon...")
			dnsRes, err := reconnaissance.DNSRecon(autoTarget)
			if err == nil {
				color.Green("✅ DNS Records: %v", dnsRes.Records)
			} else {
				color.Red("❌ DNS recon error: %v", err)
			}
		}
		if all || mods["http"] {
			color.Yellow("🌐 Running HTTP recon...")
			httpRes, err := reconnaissance.HTTPRecon("http://" + autoTarget)
			if err == nil {
				color.Green("✅ HTTP Status: %d, Headers: %v", httpRes.Status, httpRes.Headers)
			} else {
				color.Red("❌ HTTP recon error: %v", err)
			}
		}
		if (all || mods["smb"]) && portResults != nil {
			if port, ok := portResults[445]; ok && port["state"] == "OPEN" {
				color.Yellow("🔒 Running SMB enumeration...")
				smbEnum := network_vulnerabilities.NewSMBEnumerator(autoTarget)
				smbResults = smbEnum.EnumerateShares()
				color.Green("✅ SMB enumeration complete!")
			}
		}
		color.Cyan("\n🎯 --- Automated Recon Summary --- 🎯")
		if len(subdomains) > 0 {
			color.Green("Subdomains found: %d", len(subdomains))
		}
		if portResults != nil {
			color.Green("Open ports:")
			for port, res := range portResults {
				if res["state"] == "OPEN" {
					color.Magenta("  ➡️ %d (banner: %s)", port, strings.TrimSpace(res["banner"]))
				}
			}
		}
		if len(smbResults) > 0 {
			color.Green("SMB Shares:")
			for _, share := range smbResults {
				color.Magenta("  ➡️ %s (%s)", share["share"], share["access"])
			}
		}
		color.Cyan("--- End of Summary --- 🏁\n")
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

func printBanner() {
	banner := `
 ________  ________  _______      ___    ___ ________  _______   ________   _______  _________  ________  ________  _________  _______      
|\   __  \|\   __  \|\  ___ \    |\  \  /  /|\   __  \|\  ___ \ |\   ___  \|\  ___ \|\___   ___\\   __  \|\   __  \|\___   ___\\  ___ \     
\ \  \|\  \ \  \|\  \ \   __/|   \ \  \/  / | \  \|\  \ \   __/|\ \  \\ \  \ \   __/\|___ \  \_\ \  \|\  \ \  \|\  \|___ \  \_\ \   __/|    
 \ \   __  \ \   ____\ \  \_|/__  \ \    / / \ \   ____\ \  \_|/_\ \  \\ \  \ \  \_|/__  \ \  \ \ \   _  _\ \   __  \   \ \  \ \ \  \_|/__  
  \ \  \ \  \ \  \___|\ \  \_|\ \  /     \/   \ \  \___|\ \  \_|\ \ \  \\ \  \ \  \_|\ \  \ \  \ \ \  \\  \\ \  \ \  \   \ \  \ \ \  \_|\ \ 
   \ \__\ \__\ \__\    \ \_______\/  /\   \    \ \__\    \ \_______\ \__\\ \__\ \_______\  \ \__\ \ \__\\ _\\ \__\ \__\   \ \__\ \ \_______\
    \|__|\|__|\|__|     \|_______/__/ /\ __\    \|__|     \|_______|\|__| \|__|\|_______|   \|__|  \|__|\|__|\|__|\|__|    \|__|  \|_______|
                                 |__|/ \|__|                                                                                                
`
	color.Cyan(banner)
	color.Magenta("ApexPenetrateGo v%s - By Cyber Enthusiasts for Cyber Enthusiasts!", version)
	color.Yellow("https://github.com/YourUsername/apexPenetrateGo\n")
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
