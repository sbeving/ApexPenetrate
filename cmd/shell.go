// cmd/shell.go
package cmd

import (
	"apexPenetrateGo/internal/core"
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	// Import all modules to ensure they're registered
	_ "apexPenetrateGo/internal/modules/network_vulnerabilities"
	_ "apexPenetrateGo/internal/modules/reconnaissance"
	_ "apexPenetrateGo/internal/modules/web_vulnerabilities"
)

type ShellContext struct {
	CurrentModule core.Plugin
	Options       map[string]interface{}
}

var shellCtx = &ShellContext{Options: map[string]interface{}{}}

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
			res, err := shellCtx.CurrentModule.Run(target, shellCtx.Options)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
			} else {
				fmt.Printf("Result: %v\n", res)
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
		default:
			fmt.Println("Unknown command. Try: search, use, set, info, show options, run, back, exit")
		}
	}
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
