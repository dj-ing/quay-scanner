// internal/config/config.go
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// QuayConfig holds settings specific to the Quay client
type QuayConfig struct {
	APIBaseURL     string `yaml:"api_base_url"`
	TimeoutSeconds int    `yaml:"timeout_seconds"` // Load as int, convert to duration later
	UserAgent      string `yaml:"user_agent"`
}

// AppConfig is the top-level configuration structure
type AppConfig struct {
	Quay QuayConfig `yaml:"quay"`
	// Add other configuration sections here (e.g., logging, defaults) if needed
}

// DefaultConfig returns a configuration with default values.
func DefaultConfig() AppConfig {
	return AppConfig{
		Quay: QuayConfig{
			APIBaseURL:     "https://quay.io/api/v1/",      // Default Quay API URL
			TimeoutSeconds: 15,                             // Default timeout in seconds
			UserAgent:      "golang-quay-vuln-scanner/1.1", // Updated default agent
		},
	}
}

// GetTimeout converts TimeoutSeconds to time.Duration
func (qc QuayConfig) GetTimeout() time.Duration {
	// Ensure a minimum reasonable timeout if config is invalid
	if qc.TimeoutSeconds <= 0 {
		return 5 * time.Second // Minimum fallback timeout
	}
	return time.Duration(qc.TimeoutSeconds) * time.Second
}

// LoadConfig reads the configuration file or returns defaults.
// It returns the loaded config and an error ONLY if reading/parsing fails.
// If the file doesn't exist, it returns defaults and nil error, printing a warning.
func LoadConfig(filePath string) (AppConfig, error) {
	cfg := DefaultConfig() // Start with defaults

	absPath, err := filepath.Abs(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Could not determine absolute path for config '%s': %v. Using defaults.\n", filePath, err)
		return cfg, nil // Return defaults if path is problematic
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Config file doesn't exist is not a fatal error, use defaults
			fmt.Fprintf(os.Stderr, "Info: Config file '%s' not found, using default settings.\n", absPath)
			return cfg, nil
		}
		// Other file reading error *is* potentially fatal or indicates misconfiguration
		return cfg, fmt.Errorf("failed to read config file '%s': %w", absPath, err)
	}

	// Unmarshal the YAML data into the config struct
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return cfg, fmt.Errorf("failed to parse YAML config file '%s': %w", absPath, err)
	}

	// --- Basic Validation ---
	if cfg.Quay.APIBaseURL == "" {
		fmt.Fprintf(os.Stderr, "Warning: quay.api_base_url is empty in config '%s', using default: %s\n", absPath, DefaultConfig().Quay.APIBaseURL)
		cfg.Quay.APIBaseURL = DefaultConfig().Quay.APIBaseURL
	}
	if !isValidURL(cfg.Quay.APIBaseURL) {
		// Or return an error if URL must be valid
		fmt.Fprintf(os.Stderr, "Warning: quay.api_base_url ('%s') in config '%s' might be invalid, attempting to use anyway.\n", cfg.Quay.APIBaseURL, absPath)
	}
	if cfg.Quay.TimeoutSeconds <= 0 {
		fmt.Fprintf(os.Stderr, "Warning: quay.timeout_seconds must be positive in config '%s', using default: %d\n", absPath, DefaultConfig().Quay.TimeoutSeconds)
		cfg.Quay.TimeoutSeconds = DefaultConfig().Quay.TimeoutSeconds
	}
	// UserAgent can reasonably be empty, so no strict validation unless required.

	fmt.Fprintf(os.Stderr, "Info: Loaded configuration from '%s'\n", absPath)
	return cfg, nil
}

// isValidURL is a basic check (can be expanded if needed)
func isValidURL(u string) bool {
	// Very basic check, net/url.Parse is more robust but might allow relative paths etc.
	return len(u) > 0 && (filepath.HasPrefix(u, "http://") || filepath.HasPrefix(u, "https://"))
}
