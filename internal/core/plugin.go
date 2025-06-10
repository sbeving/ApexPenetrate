// internal/core/plugin.go
package core

// ModuleOption describes a configurable option for a plugin/module
// Type can be: string, int, bool, stringslice, etc.
type ModuleOption struct {
	Name        string
	Type        string
	Default     interface{}
	Description string
	Required    bool
}

// Plugin is the interface for all modules/plugins.
type Plugin interface {
	Name() string
	Description() string
	Run(target string, options map[string]interface{}) (interface{}, error)
	Category() string        // e.g. "recon", "web", "network"
	Options() []ModuleOption // configurable options for the module
	Help() string            // detailed help and usage examples
}

var (
	pluginRegistry = make(map[string]Plugin)
	enabledPlugins = make(map[string]bool)
)

// RegisterPlugin adds a plugin to the registry
func RegisterPlugin(p Plugin) {
	pluginRegistry[p.Name()] = p
	enabledPlugins[p.Name()] = true // enabled by default
}

// ListPlugins returns all registered plugins
func ListPlugins() []Plugin {
	plugins := []Plugin{}
	for _, p := range pluginRegistry {
		plugins = append(plugins, p)
	}
	return plugins
}

// EnablePlugin enables a plugin by name
func EnablePlugin(name string) {
	enabledPlugins[name] = true
}

// DisablePlugin disables a plugin by name
func DisablePlugin(name string) {
	enabledPlugins[name] = false
}

// IsPluginEnabled checks if a plugin is enabled
func IsPluginEnabled(name string) bool {
	enabled, ok := enabledPlugins[name]
	return ok && enabled
}

// GetPlugin returns a plugin by name
func GetPlugin(name string) Plugin {
	return pluginRegistry[name]
}

// GetEnabledPlugins returns all enabled plugins
func GetEnabledPlugins() []Plugin {
	plugins := []Plugin{}
	for name, enabled := range enabledPlugins {
		if enabled {
			plugins = append(plugins, pluginRegistry[name])
		}
	}
	return plugins
}
