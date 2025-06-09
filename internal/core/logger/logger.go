// internal/core/logger/logger.go
package logger

import (
	"os"

	"github.com/sirupsen/logrus" // Using logrus for structured logging
)

var log *logrus.Logger

func init() {
	log = logrus.New()
	log.SetOutput(os.Stdout) // Default output to stdout
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
		DisableColors: false, // Colors are good for console, can be disabled for files
	})
	log.SetLevel(logrus.InfoLevel) // Default level is Info
}

// SetupLogger configures the logger based on the provided level string.
func SetupLogger(level string) {
	switch level {
	case "debug":
		log.SetLevel(logrus.DebugLevel)
	case "info":
		log.SetLevel(logrus.InfoLevel)
	case "warn":
		log.SetLevel(logrus.WarnLevel)
	case "error":
		log.SetLevel(logrus.ErrorLevel)
	default:
		log.SetLevel(logrus.InfoLevel) // Default to info if unknown level
	}
}

// GetLogger returns the configured logger instance.
func GetLogger() *logrus.Logger {
	return log
}
