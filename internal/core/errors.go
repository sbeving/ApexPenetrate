// internal/core/errors.go
package core

import "errors"

// Define custom errors for better error handling and classification
var (
	ErrNetworkTimeout = errors.New("network request timed out")
	ErrNetworkError   = errors.New("network error occurred")
	ErrModuleError    = errors.New("module specific error")
	ErrOutputFormat   = errors.New("unsupported output format")
	ErrFileWrite      = errors.New("failed to write to file")
)
