// internal/core/plugin_dependency.go
package core

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// PluginDependency represents a dependency between plugins
type PluginDependency struct {
	PluginID    string `json:"plugin_id"`
	DependsOn   string `json:"depends_on"`
	Version     string `json:"version,omitempty"`
	Optional    bool   `json:"optional"`
	Description string `json:"description"`
}

// PluginCapability represents what a plugin can provide
type PluginCapability struct {
	Name        string                 `json:"name"`
	Version     string                 `json:"version"`
	Description string                 `json:"description"`
	Inputs      []CapabilityParameter  `json:"inputs"`
	Outputs     []CapabilityParameter  `json:"outputs"`
}

// CapabilityParameter describes input/output parameters
type CapabilityParameter struct {
	Name        string      `json:"name"`
	Type        string      `json:"type"`
	Required    bool        `json:"required"`
	Description string      `json:"description"`
	Default     interface{} `json:"default,omitempty"`
}

// PluginMetadata contains extended plugin information
type PluginMetadata struct {
	Plugin           Plugin                 `json:"-"`
	ID               string                 `json:"id"`
	Version          string                 `json:"version"`
	Author           string                 `json:"author"`
	License          string                 `json:"license"`
	Homepage         string                 `json:"homepage"`
	Repository       string                 `json:"repository"`
	Keywords         []string               `json:"keywords"`
	Dependencies     []PluginDependency     `json:"dependencies"`
	Capabilities     []PluginCapability     `json:"capabilities"`
	RequiredInputs   []CapabilityParameter  `json:"required_inputs"`
	ProvidedOutputs  []CapabilityParameter  `json:"provided_outputs"`
	InstallDate      time.Time              `json:"install_date"`
	LastUsed         time.Time              `json:"last_used"`
	UsageCount       int                    `json:"usage_count"`
	PerformanceStats PluginPerformanceStats `json:"performance_stats"`
	Enabled          bool                   `json:"enabled"`
	LoadPriority     int                    `json:"load_priority"`
}

// PluginPerformanceStats tracks plugin performance
type PluginPerformanceStats struct {
	AverageExecutionTime time.Duration `json:"average_execution_time"`
	TotalExecutionTime   time.Duration `json:"total_execution_time"`
	SuccessRate          float64       `json:"success_rate"`
	ErrorCount           int           `json:"error_count"`
	LastExecutionTime    time.Duration `json:"last_execution_time"`
	LastError            string        `json:"last_error,omitempty"`
}

// PluginDependencyManager handles plugin dependencies and capabilities
type PluginDependencyManager struct {
	plugins       map[string]*PluginMetadata
	capabilities  map[string][]string // capability -> list of plugin IDs
	dependencies  map[string][]PluginDependency
	loadOrder     []string
	initialized   bool
}

// NewPluginDependencyManager creates a new dependency manager
func NewPluginDependencyManager() *PluginDependencyManager {
	return &PluginDependencyManager{
		plugins:      make(map[string]*PluginMetadata),
		capabilities: make(map[string][]string),
		dependencies: make(map[string][]PluginDependency),
		loadOrder:    []string{},
		initialized:  false,
	}
}

// RegisterPluginWithMetadata registers a plugin with extended metadata
func (pdm *PluginDependencyManager) RegisterPluginWithMetadata(plugin Plugin, metadata PluginMetadata) error {
	metadata.Plugin = plugin
	metadata.ID = plugin.Name()
	metadata.InstallDate = time.Now()
	metadata.Enabled = true
	
	// Validate dependencies
	for _, dep := range metadata.Dependencies {
		if !dep.Optional {
			if _, exists := pdm.plugins[dep.DependsOn]; !exists {
				return fmt.Errorf("required dependency %s not found for plugin %s", dep.DependsOn, metadata.ID)
			}
		}
	}
	
	// Store plugin metadata
	pdm.plugins[metadata.ID] = &metadata
	pdm.dependencies[metadata.ID] = metadata.Dependencies
	
	// Register capabilities
	for _, capability := range metadata.Capabilities {
		if pdm.capabilities[capability.Name] == nil {
			pdm.capabilities[capability.Name] = []string{}
		}
		pdm.capabilities[capability.Name] = append(pdm.capabilities[capability.Name], metadata.ID)
	}
	
	// Register with core plugin system
	RegisterPlugin(plugin)
	
	// Recalculate load order
	pdm.calculateLoadOrder()
	
	return nil
}

// calculateLoadOrder determines the order plugins should be loaded based on dependencies
func (pdm *PluginDependencyManager) calculateLoadOrder() {
	var order []string
	visited := make(map[string]bool)
	visiting := make(map[string]bool)
	
	var visit func(string) error
	visit = func(pluginID string) error {
		if visiting[pluginID] {
			return fmt.Errorf("circular dependency detected for plugin %s", pluginID)
		}
		if visited[pluginID] {
			return nil
		}
		
		visiting[pluginID] = true
		
		// Visit dependencies first
		if deps, exists := pdm.dependencies[pluginID]; exists {
			for _, dep := range deps {
				if !dep.Optional { // Only process required dependencies
					if err := visit(dep.DependsOn); err != nil {
						return err
					}
				}
			}
		}
		
		visiting[pluginID] = false
		visited[pluginID] = true
		order = append(order, pluginID)
		
		return nil
	}
	
	// Visit all plugins
	for pluginID := range pdm.plugins {
		if !visited[pluginID] {
			if err := visit(pluginID); err != nil {
				// Handle circular dependencies - for now, just continue
				continue
			}
		}
	}
	
	pdm.loadOrder = order
}

// GetLoadOrder returns the calculated plugin load order
func (pdm *PluginDependencyManager) GetLoadOrder() []string {
	return pdm.loadOrder
}

// GetPluginsByCapability returns plugins that provide a specific capability
func (pdm *PluginDependencyManager) GetPluginsByCapability(capability string) []string {
	return pdm.capabilities[capability]
}

// GetPluginMetadata returns metadata for a specific plugin
func (pdm *PluginDependencyManager) GetPluginMetadata(pluginID string) *PluginMetadata {
	return pdm.plugins[pluginID]
}

// CheckDependencies verifies that all plugin dependencies are satisfied
func (pdm *PluginDependencyManager) CheckDependencies() map[string][]string {
	issues := make(map[string][]string)
	
	for pluginID, metadata := range pdm.plugins {
		for _, dep := range metadata.Dependencies {
			if !dep.Optional {
				if depMetadata, exists := pdm.plugins[dep.DependsOn]; !exists {
					if issues[pluginID] == nil {
						issues[pluginID] = []string{}
					}
					issues[pluginID] = append(issues[pluginID], fmt.Sprintf("Missing required dependency: %s", dep.DependsOn))
				} else if !depMetadata.Enabled {
					if issues[pluginID] == nil {
						issues[pluginID] = []string{}
					}
					issues[pluginID] = append(issues[pluginID], fmt.Sprintf("Required dependency disabled: %s", dep.DependsOn))
				}
			}
		}
	}
	
	return issues
}

// ExecuteWithDependencies executes a plugin ensuring its dependencies are available
func (pdm *PluginDependencyManager) ExecuteWithDependencies(pluginID, target string, options map[string]interface{}) (interface{}, error) {
	metadata := pdm.plugins[pluginID]
	if metadata == nil {
		return nil, fmt.Errorf("plugin %s not found", pluginID)
	}
	
	if !metadata.Enabled {
		return nil, fmt.Errorf("plugin %s is disabled", pluginID)
	}
	
	// Check dependencies
	for _, dep := range metadata.Dependencies {
		if !dep.Optional {
			depMetadata := pdm.plugins[dep.DependsOn]
			if depMetadata == nil || !depMetadata.Enabled {
				return nil, fmt.Errorf("dependency %s not available for plugin %s", dep.DependsOn, pluginID)
			}
		}
	}
	
	// Record execution start time
	startTime := time.Now()
	
	// Execute the plugin
	result, err := metadata.Plugin.Run(target, options)
	
	// Update performance statistics
	executionTime := time.Since(startTime)
	pdm.updatePerformanceStats(pluginID, executionTime, err)
	
	return result, err
}

// updatePerformanceStats updates plugin performance statistics
func (pdm *PluginDependencyManager) updatePerformanceStats(pluginID string, executionTime time.Duration, err error) {
	metadata := pdm.plugins[pluginID]
	if metadata == nil {
		return
	}
	
	stats := &metadata.PerformanceStats
	metadata.UsageCount++
	metadata.LastUsed = time.Now()
	
	// Update execution time statistics
	if stats.AverageExecutionTime == 0 {
		stats.AverageExecutionTime = executionTime
	} else {
		// Simple moving average
		stats.AverageExecutionTime = (stats.AverageExecutionTime + executionTime) / 2
	}
	
	stats.TotalExecutionTime += executionTime
	stats.LastExecutionTime = executionTime
	
	// Update error statistics
	if err != nil {
		stats.ErrorCount++
		stats.LastError = err.Error()
	}
	
	// Calculate success rate
	if metadata.UsageCount > 0 {
		stats.SuccessRate = float64(metadata.UsageCount-stats.ErrorCount) / float64(metadata.UsageCount)
	}
}

// GetPluginChain returns a chain of plugins based on capabilities
func (pdm *PluginDependencyManager) GetPluginChain(requiredCapabilities []string) []string {
	var chain []string
	
	for _, capability := range requiredCapabilities {
		if providers := pdm.capabilities[capability]; len(providers) > 0 {
			// For now, just pick the first provider - could be enhanced with scoring
			chain = append(chain, providers[0])
		}
	}
	
	return chain
}

// SuggestPlugins suggests plugins based on target and requirements
func (pdm *PluginDependencyManager) SuggestPlugins(target string, requirements []string) []PluginSuggestion {
	var suggestions []PluginSuggestion
	
	for _, metadata := range pdm.plugins {
		if !metadata.Enabled {
			continue
		}
		
		score := pdm.calculateRelevanceScore(metadata, target, requirements)
		if score > 0 {
			suggestions = append(suggestions, PluginSuggestion{
				Plugin:      metadata,
				Score:       score,
				Reasoning:   pdm.generateReasoning(metadata, target, requirements),
				Confidence:  pdm.calculateConfidence(metadata, score),
			})
		}
	}
	
	// Sort by score (descending)
	sort.Slice(suggestions, func(i, j int) bool {
		return suggestions[i].Score > suggestions[j].Score
	})
	
	return suggestions
}

// PluginSuggestion represents a suggested plugin with scoring
type PluginSuggestion struct {
	Plugin     *PluginMetadata `json:"plugin"`
	Score      float64         `json:"score"`
	Reasoning  string          `json:"reasoning"`
	Confidence float64         `json:"confidence"`
}

// calculateRelevanceScore calculates how relevant a plugin is for the given context
func (pdm *PluginDependencyManager) calculateRelevanceScore(metadata *PluginMetadata, target string, requirements []string) float64 {
	score := 0.0
	
	// Base score from category matching
	if strings.Contains(target, "http") && metadata.Plugin.Category() == "web" {
		score += 10.0
	} else if !strings.Contains(target, "http") && metadata.Plugin.Category() == "recon" {
		score += 10.0
	}
	
	// Score from keywords matching
	for _, req := range requirements {
		for _, keyword := range metadata.Keywords {
			if strings.Contains(strings.ToLower(keyword), strings.ToLower(req)) {
				score += 5.0
			}
		}
	}
	
	// Performance bonus
	if metadata.PerformanceStats.SuccessRate > 0.8 {
		score += 3.0
	}
	
	// Usage frequency bonus
	if metadata.UsageCount > 10 {
		score += 2.0
	}
	
	// Penalty for high error rate
	if metadata.PerformanceStats.SuccessRate < 0.5 {
		score -= 5.0
	}
	
	return score
}

// generateReasoning generates human-readable reasoning for plugin suggestion
func (pdm *PluginDependencyManager) generateReasoning(metadata *PluginMetadata, target string, requirements []string) string {
	var reasons []string
	
	if strings.Contains(target, "http") && metadata.Plugin.Category() == "web" {
		reasons = append(reasons, "Matches web application target")
	}
	
	if metadata.PerformanceStats.SuccessRate > 0.8 {
		reasons = append(reasons, fmt.Sprintf("High success rate (%.1f%%)", metadata.PerformanceStats.SuccessRate*100))
	}
	
	if metadata.UsageCount > 10 {
		reasons = append(reasons, "Frequently used plugin")
	}
	
	if len(reasons) == 0 {
		return "General compatibility"
	}
	
	return strings.Join(reasons, "; ")
}

// calculateConfidence calculates confidence in the suggestion
func (pdm *PluginDependencyManager) calculateConfidence(metadata *PluginMetadata, score float64) float64 {
	confidence := score / 20.0 // Normalize to 0-1
	
	// Adjust based on usage history
	if metadata.UsageCount > 0 {
		confidence += 0.1
	}
	
	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}
	
	return confidence
}

// EnablePlugin enables a plugin
func (pdm *PluginDependencyManager) EnablePlugin(pluginID string) error {
	metadata := pdm.plugins[pluginID]
	if metadata == nil {
		return fmt.Errorf("plugin %s not found", pluginID)
	}
	
	metadata.Enabled = true
	return nil
}

// DisablePlugin disables a plugin
func (pdm *PluginDependencyManager) DisablePlugin(pluginID string) error {
	metadata := pdm.plugins[pluginID]
	if metadata == nil {
		return fmt.Errorf("plugin %s not found", pluginID)
	}
	
	// Check if other plugins depend on this one
	dependents := pdm.getDependents(pluginID)
	if len(dependents) > 0 {
		return fmt.Errorf("cannot disable plugin %s: required by %v", pluginID, dependents)
	}
	
	metadata.Enabled = false
	return nil
}

// getDependents returns plugins that depend on the given plugin
func (pdm *PluginDependencyManager) getDependents(pluginID string) []string {
	var dependents []string
	
	for pid, deps := range pdm.dependencies {
		for _, dep := range deps {
			if dep.DependsOn == pluginID && !dep.Optional {
				dependents = append(dependents, pid)
				break
			}
		}
	}
	
	return dependents
}

// GetPluginGraph returns a dependency graph representation
func (pdm *PluginDependencyManager) GetPluginGraph() map[string]interface{} {
	graph := make(map[string]interface{})
	
	nodes := []map[string]interface{}{}
	edges := []map[string]interface{}{}
	
	// Add nodes
	for pluginID, metadata := range pdm.plugins {
		node := map[string]interface{}{
			"id":       pluginID,
			"label":    metadata.Plugin.Name(),
			"category": metadata.Plugin.Category(),
			"enabled":  metadata.Enabled,
			"usage":    metadata.UsageCount,
		}
		nodes = append(nodes, node)
	}
	
	// Add edges
	for pluginID, deps := range pdm.dependencies {
		for _, dep := range deps {
			edge := map[string]interface{}{
				"from":     dep.DependsOn,
				"to":       pluginID,
				"optional": dep.Optional,
			}
			edges = append(edges, edge)
		}
	}
	
	graph["nodes"] = nodes
	graph["edges"] = edges
	graph["load_order"] = pdm.loadOrder
	
	return graph
}

// GetCapabilityMap returns a map of capabilities to plugins
func (pdm *PluginDependencyManager) GetCapabilityMap() map[string][]string {
	return pdm.capabilities
}

// ValidatePluginCompatibility checks if plugins can work together
func (pdm *PluginDependencyManager) ValidatePluginCompatibility(pluginIDs []string) map[string][]string {
	issues := make(map[string][]string)
	
	// Check for conflicting capabilities
	capabilityProviders := make(map[string][]string)
	
	for _, pluginID := range pluginIDs {
		metadata := pdm.plugins[pluginID]
		if metadata == nil {
			continue
		}
		
		for _, capability := range metadata.Capabilities {
			if capabilityProviders[capability.Name] == nil {
				capabilityProviders[capability.Name] = []string{}
			}
			capabilityProviders[capability.Name] = append(capabilityProviders[capability.Name], pluginID)
		}
	}
	
	// Report conflicts
	for capability, providers := range capabilityProviders {
		if len(providers) > 1 {
			for _, provider := range providers {
				if issues[provider] == nil {
					issues[provider] = []string{}
				}
				others := []string{}
				for _, p := range providers {
					if p != provider {
						others = append(others, p)
					}
				}
				issues[provider] = append(issues[provider], 
					fmt.Sprintf("Capability conflict '%s' with: %s", capability, strings.Join(others, ", ")))
			}
		}
	}
	
	return issues
}

// GetPerformanceReport generates a performance report for all plugins
func (pdm *PluginDependencyManager) GetPerformanceReport() map[string]interface{} {
	report := make(map[string]interface{})
	
	var totalUsage int
	var totalExecutionTime time.Duration
	pluginStats := []map[string]interface{}{}
	
	for pluginID, metadata := range pdm.plugins {
		totalUsage += metadata.UsageCount
		totalExecutionTime += metadata.PerformanceStats.TotalExecutionTime
		
		pluginStats = append(pluginStats, map[string]interface{}{
			"plugin":               pluginID,
			"usage_count":          metadata.UsageCount,
			"success_rate":         metadata.PerformanceStats.SuccessRate,
			"average_exec_time":    metadata.PerformanceStats.AverageExecutionTime.String(),
			"total_exec_time":      metadata.PerformanceStats.TotalExecutionTime.String(),
			"error_count":          metadata.PerformanceStats.ErrorCount,
			"last_used":           metadata.LastUsed.Format("2006-01-02 15:04:05"),
		})
	}
	
	// Sort by usage count
	sort.Slice(pluginStats, func(i, j int) bool {
		return pluginStats[i]["usage_count"].(int) > pluginStats[j]["usage_count"].(int)
	})
	
	report["total_plugins"] = len(pdm.plugins)
	report["total_usage"] = totalUsage
	report["total_execution_time"] = totalExecutionTime.String()
	report["plugin_stats"] = pluginStats
	
	if totalUsage > 0 {
		report["average_usage_per_plugin"] = totalUsage / len(pdm.plugins)
	}
	
	return report
}

// Global dependency manager instance
var GlobalDependencyManager = NewPluginDependencyManager()
