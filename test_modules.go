// test_modules.go
package main

import (
	"apexPenetrateGo/internal/core"
	"fmt"

	// Import all modules to trigger init() functions
	_ "apexPenetrateGo/internal/modules/network_vulnerabilities"
	_ "apexPenetrateGo/internal/modules/reconnaissance"
	_ "apexPenetrateGo/internal/modules/web_vulnerabilities"
)

func main() {
	fmt.Println("🔍 Listing all registered modules:")
	plugins := core.ListPlugins()
	for _, plugin := range plugins {
		fmt.Printf("  %s - %s (%s)\n", plugin.Name(), plugin.Description(), plugin.Category())
	}
	fmt.Printf("\nTotal modules: %d\n", len(plugins))
}
