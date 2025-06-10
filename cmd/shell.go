// cmd/shell.go
package cmd

import (
	"apexPenetrateGo/internal/core"
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	// Import all modules to ensure they're registered
	_ "apexPenetrateGo/internal/modules/network_vulnerabilities"
	_ "apexPenetrateGo/internal/modules/reconnaissance"
	_ "apexPenetrateGo/internal/modules/web_vulnerabilities"
)

type ShellContext struct {
	CurrentModule core.Plugin
	Options       map[string]interface{}
	Results       map[string]interface{} // Store last results for recommendations
}

var (
	shellCtx          = &ShellContext{Options: map[string]interface{}{}, Results: map[string]interface{}{}}
	dashboardStopChan chan struct{}
	dashboardOnce     sync.Once
)

func StartShell() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("\n🦾 Welcome to ApexPenetrateGo Shell (Metasploit-style)")
	for {
		prompt := "apex> "
		if shellCtx.CurrentModule != nil {
			prompt = fmt.Sprintf("apex (%s)> ", shellCtx.CurrentModule.Name())
		}
		fmt.Print(prompt)
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "exit" || line == "quit" {
			fmt.Println("Goodbye!")
			return
		}
		args := strings.Fields(line)
		if len(args) == 0 {
			continue
		}
		switch args[0] {
		case "search":
			if len(args) < 2 {
				fmt.Println("Usage: search <keyword>")
				continue
			}
			for _, p := range core.ListPlugins() {
				if strings.Contains(strings.ToLower(p.Name()), strings.ToLower(args[1])) || strings.Contains(strings.ToLower(p.Description()), strings.ToLower(args[1])) {
					fmt.Printf("%s\t%s\t%s\n", p.Category(), p.Name(), p.Description())
				}
			}
		case "use":
			if len(args) < 2 {
				fmt.Println("Usage: use <module>")
				continue
			}
			found := false
			for _, p := range core.ListPlugins() {
				if strings.EqualFold(p.Name(), args[1]) {
					shellCtx.CurrentModule = p
					shellCtx.Options = map[string]interface{}{}
					fmt.Printf("Module '%s' selected. Type 'info' to see options.\n", p.Name())
					found = true
					break
				}
			}
			if !found {
				fmt.Println("Module not found.")
			}
		case "info":
			if shellCtx.CurrentModule == nil {
				fmt.Println("No module selected.")
				continue
			}
			fmt.Printf("\nModule: %s\nDescription: %s\nCategory: %s\n", shellCtx.CurrentModule.Name(), shellCtx.CurrentModule.Description(), shellCtx.CurrentModule.Category())
			fmt.Println("\nOptions:")
			options := shellCtx.CurrentModule.Options()
			if len(options) == 0 {
				fmt.Println("  No configurable options for this module.")
			} else {
				fmt.Printf("  %-15s %-10s %-15s %s\n", "Name", "Required", "Current Value", "Description")
				fmt.Printf("  %-15s %-10s %-15s %s\n", "----", "--------", "-------------", "-----------")
				for _, opt := range options {
					required := "no"
					if opt.Required {
						required = "yes"
					}
					currentVal := opt.Default
					if val, ok := shellCtx.Options[opt.Name]; ok {
						currentVal = val
					}
					fmt.Printf("  %-15s %-10s %-15v %s\n", opt.Name, required, currentVal, opt.Description)
				}
			}
		case "set":
			if shellCtx.CurrentModule == nil {
				fmt.Println("No module selected. Use 'use <module>' first.")
				continue
			}
			if len(args) < 3 {
				fmt.Println("Usage: set <option> <value>")
				continue
			}
			opt := args[1]
			val := strings.Join(args[2:], " ")

			// Validate option exists
			validOption := false
			for _, moduleOpt := range shellCtx.CurrentModule.Options() {
				if moduleOpt.Name == opt {
					validOption = true
					break
				}
			}
			if !validOption {
				fmt.Printf("Invalid option '%s'. Use 'info' to see available options.\n", opt)
				continue
			}

			shellCtx.Options[opt] = val
			fmt.Printf("Set %s = %s\n", opt, val)
		case "run":
			if shellCtx.CurrentModule == nil {
				fmt.Println("No module selected.")
				continue
			}

			// Check required options
			missingRequired := []string{}
			for _, opt := range shellCtx.CurrentModule.Options() {
				if opt.Required {
					if _, ok := shellCtx.Options[opt.Name]; !ok {
						missingRequired = append(missingRequired, opt.Name)
					}
				}
			}
			if len(missingRequired) > 0 {
				fmt.Printf("Missing required options: %s\n", strings.Join(missingRequired, ", "))
				continue
			}

			// Get target from options or prompt
			target := ""
			if val, ok := shellCtx.Options["target"]; ok {
				target = val.(string)
			}
			if target == "" {
				fmt.Print("Enter target: ")
				target, _ = reader.ReadString('\n')
				target = strings.TrimSpace(target)
			}

			fmt.Printf("Running %s against %s...\n", shellCtx.CurrentModule.Name(), target)
			// Start dashboard if not running
			dashboardOnce.Do(func() {
				dashboardStopChan = make(chan struct{})
				go core.StartLiveDashboard(dashboardStopChan)
			})
			// Update dashboard: increment running
			core.UpdateDashboard(1, 0, 0, 0) // Running 1 module, completed 0 for now
			res, err := shellCtx.CurrentModule.Run(target, shellCtx.Options)
			// Update dashboard: module completed
			core.UpdateDashboard(0, 1, extractOpenPorts(res), extractVulnsFound(res))
			if dashboardStopChan != nil {
				close(dashboardStopChan)
				dashboardOnce = sync.Once{} // Reset for next run
			}
			if err != nil {
				fmt.Printf("Error: %v\n", err)
			} else {
				fmt.Printf("Result: %v\n", res)
				// Save result for recommendations
				if shellCtx.Results == nil {
					shellCtx.Results = map[string]interface{}{}
				}
				shellCtx.Results[shellCtx.CurrentModule.Name()] = res
				// Call recommendations after run
				SuggestNextModules(shellCtx.Results)
			}
		case "back":
			shellCtx.CurrentModule = nil
			shellCtx.Options = map[string]interface{}{}
			fmt.Println("Back to main shell.")
		case "show":
			if len(args) > 1 && args[1] == "options" {
				if shellCtx.CurrentModule == nil {
					fmt.Println("No module selected.")
					continue
				}
				// Same as info but just options
				fmt.Println("\nModule Options:")
				options := shellCtx.CurrentModule.Options()
				if len(options) == 0 {
					fmt.Println("  No configurable options for this module.")
				} else {
					fmt.Printf("  %-15s %-10s %-15s %s\n", "Name", "Required", "Current Value", "Description")
					fmt.Printf("  %-15s %-10s %-15s %s\n", "----", "--------", "-------------", "-----------")
					for _, opt := range options {
						required := "no"
						if opt.Required {
							required = "yes"
						}
						currentVal := opt.Default
						if val, ok := shellCtx.Options[opt.Name]; ok {
							currentVal = val
						}
						fmt.Printf("  %-15s %-10s %-15v %s\n", opt.Name, required, currentVal, opt.Description)
					}
				}
			} else {
				fmt.Println("Usage: show options")
			}
		case "suggest":
			SuggestNextModules(shellCtx.Results)
			continue
		case "help":
			if len(args) < 2 {
				fmt.Println("Usage: help <module>")
				fmt.Println("Available modules:")
				for _, p := range core.ListPlugins() {
					fmt.Printf("  %-20s - %s\n", p.Name(), p.Description())
				}
				continue
			}
			moduleName := args[1]
			found := false
			for _, p := range core.ListPlugins() {
				if strings.EqualFold(p.Name(), moduleName) {
					fmt.Println(p.Help())
					found = true
					break
				}
			}
			if !found {
				fmt.Printf("Module '%s' not found.\n", moduleName)
			}
			continue
		case "chain":
			handleChainCommand(args, reader)
			continue
		default:
			fmt.Println("Unknown command. Try: search, use, set, info, show options, run, back, chain, suggest, help, exit")
		}
	}
}

// handleChainCommand handles chain-related commands
func handleChainCommand(args []string, reader *bufio.Reader) {
	if len(args) < 2 {
		fmt.Println("Usage: chain <subcommand>")
		fmt.Println("Subcommands:")
		fmt.Println("  list                 - List available chains")
		fmt.Println("  create <name>        - Interactively create a new chain")
		fmt.Println("  run <name> <target>  - Execute a chain")
		fmt.Println("  load <file>          - Load chains from JSON file")
		fmt.Println("  save <file>          - Save chains to JSON file")
		return
	}

	automationEngine := core.NewAutomationEngine()
	automationEngine.CreateDefaultChains()

	switch args[1] {
	case "list":
		chains := automationEngine.ListChains()
		if len(chains) == 0 {
			fmt.Println("No chains available. Use 'chain create <name>' to create one.")
			return
		}
		fmt.Println("\n🔗 Available Scan Chains:")
		for _, chain := range chains {
			fmt.Printf("  %-20s %s (%d steps)\n", chain.Name, chain.Description, len(chain.Steps))
		}

	case "create":
		if len(args) < 3 {
			fmt.Println("Usage: chain create <name>")
			return
		}
		createInteractiveChain(args[2], reader, automationEngine)

	case "run":
		if len(args) < 4 {
			fmt.Println("Usage: chain run <name> <target>")
			return
		}
		chainName := args[2]
		target := args[3]
		fmt.Printf("🚀 Executing chain '%s' on target '%s'...\n", chainName, target)

		execution, err := automationEngine.ExecuteChain(chainName, target)
		if err != nil {
			fmt.Printf("❌ Chain execution failed: %v\n", err)
			return
		}

		fmt.Printf("✅ Chain execution completed in %v\n", execution.EndTime.Sub(execution.StartTime))
		fmt.Printf("📊 Executed %d steps: %s\n", len(execution.ExecutedSteps), strings.Join(execution.ExecutedSteps, ", "))

	case "load":
		if len(args) < 3 {
			fmt.Println("Usage: chain load <file>")
			return
		}
		err := automationEngine.LoadChains(args[2])
		if err != nil {
			fmt.Printf("❌ Failed to load chains: %v\n", err)
		} else {
			fmt.Printf("✅ Chains loaded from %s\n", args[2])
		}

	case "save":
		if len(args) < 3 {
			fmt.Println("Usage: chain save <file>")
			return
		}
		err := automationEngine.SaveChains(args[2])
		if err != nil {
			fmt.Printf("❌ Failed to save chains: %v\n", err)
		} else {
			fmt.Printf("✅ Chains saved to %s\n", args[2])
		}

	default:
		fmt.Printf("Unknown chain subcommand: %s\n", args[1])
	}
}

// createInteractiveChain creates a scan chain interactively
func createInteractiveChain(name string, reader *bufio.Reader, automationEngine *core.AutomationEngine) {
	fmt.Printf("🔗 Creating scan chain: %s\n", name)

	fmt.Print("Description: ")
	description, _ := reader.ReadString('\n')
	description = strings.TrimSpace(description)

	fmt.Print("Output path (default: ./reports): ")
	outputPath, _ := reader.ReadString('\n')
	outputPath = strings.TrimSpace(outputPath)
	if outputPath == "" {
		outputPath = "./reports"
	}

	chain := core.ScanChain{
		Name:        name,
		Description: description,
		Steps:       []core.ChainStep{},
		Options:     map[string]interface{}{},
		OutputPath:  outputPath,
	}

	// Add steps interactively
	for {
		fmt.Print("\nAdd a step? (y/n): ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(strings.ToLower(choice))

		if choice != "y" && choice != "yes" {
			break
		}

		step := createInteractiveStep(reader)
		chain.Steps = append(chain.Steps, step)
		fmt.Printf("✅ Added step: %s\n", step.Name)
	}

	automationEngine.AddChain(chain)
	fmt.Printf("✅ Chain '%s' created with %d steps!\n", name, len(chain.Steps))
}

// createInteractiveStep creates a chain step interactively
func createInteractiveStep(reader *bufio.Reader) core.ChainStep {
	fmt.Print("Step name: ")
	name, _ := reader.ReadString('\n')
	name = strings.TrimSpace(name)

	fmt.Print("Module name: ")
	module, _ := reader.ReadString('\n')
	module = strings.TrimSpace(module)

	fmt.Print("Description: ")
	description, _ := reader.ReadString('\n')
	description = strings.TrimSpace(description)

	step := core.ChainStep{
		Module:      module,
		Name:        name,
		Description: description,
		Options:     map[string]interface{}{},
		Conditions:  []core.ChainCondition{},
		OnSuccess:   []string{},
		OnFailure:   []string{},
	}

	// Add conditions
	fmt.Print("Add conditions? (y/n): ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(strings.ToLower(choice))

	if choice == "y" || choice == "yes" {
		fmt.Println("Available condition types:")
		fmt.Println("  1. result_contains - Execute if previous results contain text")
		fmt.Println("  2. ports_found - Execute if open ports were found")
		fmt.Println("  3. vulns_found - Execute if vulnerabilities were found")

		fmt.Print("Choose condition type (1-3): ")
		condChoice, _ := reader.ReadString('\n')
		condChoice = strings.TrimSpace(condChoice)

		var condition core.ChainCondition
		switch condChoice {
		case "1":
			condition.Type = "result_contains"
			fmt.Print("Text to search for: ")
			value, _ := reader.ReadString('\n')
			condition.Value = strings.TrimSpace(value)
			condition.Operator = "contains"
		case "2":
			condition.Type = "ports_found"
			condition.Value = true
			condition.Operator = "equals"
		case "3":
			condition.Type = "vulns_found"
			condition.Value = true
			condition.Operator = "equals"
		}

		if condition.Type != "" {
			step.Conditions = append(step.Conditions, condition)
		}
	}

	return step
}

// SuggestNextModules analyzes results and prints recommended next modules
func SuggestNextModules(result interface{}) {
	fmt.Println("\n🤖 AI-Powered Module Recommendations:")
	recommended := map[string]bool{}

	// 1. If open ports found
	if ports, ok := result.(map[string]interface{})["open_ports"]; ok && ports != nil {
		fmt.Println("  🔎 Detected open ports. Recommended next modules:")
		fmt.Println("    - ServiceVersionDetect (banner grabbing)")
		recommended["ServiceVersionDetect"] = true
		fmt.Println("    - CVEScanner (vulnerability scan)")
		recommended["CVEScanner"] = true
		fmt.Println("    - Web Vulns (XSS, SQLi, CORS, DirFuzzer)")
		recommended["XSSScanner"] = true
		recommended["SQLIScanner"] = true
		recommended["CORSTester"] = true
		recommended["DirFuzzer"] = true
	}
	// 2. If subdomains found
	if subdomains, ok := result.(map[string]interface{})["subdomains"]; ok && subdomains != nil {
		fmt.Println("  🌐 Subdomains found. Try:")
		fmt.Println("    - DNSRecon, HTTPRecon, DirFuzzer")
		recommended["DNSRecon"] = true
		recommended["HTTPRecon"] = true
		recommended["DirFuzzer"] = true
	}
	// 3. If tech fingerprint found
	if tech, ok := result.(map[string]interface{})["tech_fingerprint"]; ok && tech != nil {
		fmt.Println("  🧬 Technologies detected. Try:")
		fmt.Println("    - XSSScanner, SQLIScanner, CORSTester, OpenRedirect")
		recommended["XSSScanner"] = true
		recommended["SQLIScanner"] = true
		recommended["CORSTester"] = true
		recommended["OpenRedirect"] = true
	}
	// 4. If vulnerabilities found
	if vulns, ok := result.(map[string]interface{})["vulnerabilities"]; ok && vulns != nil {
		fmt.Println("  🚨 Vulnerabilities detected. Next steps:")
		fmt.Println("    - Generate report (report)")
		fmt.Println("    - Try exploit or playground modules")
		recommended["report"] = true
		recommended["playground"] = true
	}
	if len(recommended) == 0 {
		fmt.Println("  🤔 No specific recommendations. Try running a recon or port scan module first!")
	}
}

// Helpers to extract stats for dashboard
func extractOpenPorts(res interface{}) int {
	if m, ok := res.(map[string]interface{}); ok {
		if ports, ok := m["open_ports"]; ok {
			if arr, ok := ports.([]int); ok {
				return len(arr)
			}
			if arr, ok := ports.([]interface{}); ok {
				return len(arr)
			}
		}
	}
	return 0
}

func extractVulnsFound(res interface{}) int {
	if m, ok := res.(map[string]interface{}); ok {
		if vulns, ok := m["vulnerabilities"]; ok {
			if arr, ok := vulns.([]interface{}); ok {
				return len(arr)
			}
		}
	}
	return 0
}

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "shell",
		Short: "Interactive Metasploit-style shell",
		Run: func(cmd *cobra.Command, args []string) {
			StartShell()
		},
	})
}
