// internal/core/plugin.go
package core

// Plugin is the interface for all modules/plugins.
type Plugin interface {
	Name() string
	Description() string
	Run(target string, options map[string]interface{}) (interface{}, error)
}
