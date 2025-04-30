// cmd/quay-scanner/main.go
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	// Import the new config package
	"quay-scanner/internal/config"
	"quay-scanner/internal/formatter"
	"quay-scanner/internal/quay"
)

// --- Constants ---
// const defaultWorkers = 5 // Keep this or move to config if desired
const defaultConfigPath = "config/config.yaml" // Define default config path

// CliConfig holds configuration derived ONLY from flags and environment variables
// Renamed from Config to avoid clash with AppConfig
type CliConfig struct {
	ImageURL     string
	InputFile    string
	OutputFormat string
	Verbose      bool
	Token        string
	NumWorkers   int
	ConfigFile   string // Add flag for custom config file path
}

// --- Main Execution Flow ---

func main() {
	// 1. Parse flags and initialize CLI configuration
	cliCfg, err := parseFlags() // Renamed function
	if err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		flag.Usage()
		os.Exit(1)
	}

	// 2. Setup logging based on CLI configuration
	setupLogging(cliCfg.Verbose)

	// 3. Load application configuration from file
	appCfg, err := config.LoadConfig(cliCfg.ConfigFile) // Use path from flag
	if err != nil {
		// LoadConfig now only returns error on read/parse failure
		// File not found is handled internally with defaults/warnings
		fmt.Fprintf(os.Stderr, "Error processing configuration file '%s': %v\n", cliCfg.ConfigFile, err)
		os.Exit(1) // Exit if config file is present but invalid
	}
	log.Printf("INFO: Using Quay API Base URL: %s", appCfg.Quay.APIBaseURL)
	log.Printf("INFO: Using HTTP Timeout: %v", appCfg.Quay.GetTimeout())
	log.Printf("INFO: Using User-Agent: %s", appCfg.Quay.UserAgent)

	// 4. Load the list of image URLs to process (using CLI config)
	imageURLs, err := loadImageURLs(cliCfg) // Pass CLI config
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading image URLs: %v\n", err)
		os.Exit(1)
	}
	if len(imageURLs) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No image URLs specified or found in the input file.")
		os.Exit(1)
	}
	log.Printf("INFO: Preparing to process %d image(s).\n", len(imageURLs))

	// 5. Create the Quay API client using merged config (App Cfg + CLI Cfg)
	quayClient, err := quay.NewClient(
		appCfg.Quay.APIBaseURL,   // From config file
		cliCfg.Token,             // From flag/env
		appCfg.Quay.GetTimeout(), // From config file
		appCfg.Quay.UserAgent,    // From config file
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating Quay client: %v\n", err)
		os.Exit(1)
	}

	// 6. Run the worker pool to process images concurrently
	log.Printf("INFO: Starting vulnerability scan with %d workers...\n", cliCfg.NumWorkers)
	results := runWorkerPool(imageURLs, quayClient, cliCfg.NumWorkers)
	log.Println("INFO: Vulnerability scan finished.")

	// 7. Format and output the results
	log.Printf("INFO: Formatting output as %s...\n", cliCfg.OutputFormat)
	err = outputResults(results, cliCfg.OutputFormat, os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error formatting output: %v\n", err)
		os.Exit(1)
	}

	log.Println("INFO: Done.")
}

// --- Helper Functions ---

// parseFlags defines flags, parses them, validates, and returns a CliConfig struct.
// Renamed from parseFlagsAndConfig
func parseFlags() (CliConfig, error) {
	cfg := CliConfig{} // Use CliConfig struct now
	// Define flags
	flag.StringVar(&cfg.ImageURL, "image", "", "Single Quay.io image URL (mutually exclusive with -file)")
	flag.StringVar(&cfg.InputFile, "file", "", "Path to JSON or YAML file containing a list of image URLs (mutually exclusive with -image)")
	flag.StringVar(&cfg.OutputFormat, "format", "human", "Output format: 'json' or 'human'")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose logging")
	flag.StringVar(&cfg.Token, "token", "", "Quay API Bearer Token (optional, overrides QUAY_TOKEN env var)")
	flag.IntVar(&cfg.NumWorkers, "workers", 5, "Number of concurrent workers (default: 5)")                                  // Set default here
	flag.StringVar(&cfg.ConfigFile, "config", defaultConfigPath, "Path to the application configuration file (config.yaml)") // Add config flag

	// Custom usage message (update if needed)
	flag.Usage = func() {
		// ... (keep usage message, maybe add info about -config flag) ...
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", path.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "Queries Quay.io for vulnerability information for one or more images.\n\n")
		fmt.Fprintf(os.Stderr, "Input:\n")
		fmt.Fprintf(os.Stderr, "  Provide either -image for a single image OR -file for multiple images.\n")
		fmt.Fprintf(os.Stderr, "  Input file format (JSON): {\"images\": [\"quay.io/ns/repo:tag\", ...]}}\n")
		fmt.Fprintf(os.Stderr, "  Input file format (YAML): images:\n    - quay.io/ns/repo:tag\n    - ...\n\n")
		fmt.Fprintf(os.Stderr, "Configuration:\n")
		fmt.Fprintf(os.Stderr, "  Uses settings from the file specified by -config (default: %s).\n", defaultConfigPath)
		fmt.Fprintf(os.Stderr, "Authentication:\n")
		fmt.Fprintf(os.Stderr, "  Uses QUAY_TOKEN environment variable or -token flag.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}

	// Parse command line arguments
	flag.Parse()

	// Validate flags
	if cfg.ImageURL == "" && cfg.InputFile == "" {
		return cfg, fmt.Errorf("either -image or -file flag is required")
	}
	if cfg.ImageURL != "" && cfg.InputFile != "" {
		return cfg, fmt.Errorf("-image and -file flags are mutually exclusive")
	}
	if cfg.OutputFormat != "json" && cfg.OutputFormat != "human" {
		return cfg, fmt.Errorf("invalid -format value '%s'. Must be 'json' or 'human'", cfg.OutputFormat)
	}
	if cfg.NumWorkers <= 0 {
		return cfg, fmt.Errorf("-workers must be a positive number")
	}

	// Handle token precedence (flag > env var)
	if cfg.Token == "" {
		cfg.Token = os.Getenv("QUAY_TOKEN")
		if cfg.Token != "" && cfg.Verbose { // Only log token source if verbose
			log.Println("INFO: Using token from QUAY_TOKEN environment variable.")
		}
	} else {
		if cfg.Verbose {
			log.Println("INFO: Using token from -token flag.")
		}
	}
	// Warning about missing token moved to where client is created or used if needed

	return cfg, nil
}

// setupLogging remains the same
func setupLogging(verbose bool) {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if !verbose {
		log.SetOutput(io.Discard)
	} else {
		log.SetOutput(os.Stderr)
		log.Println("Verbose logging enabled.")
	}
}

// loadImageURLs now takes CliConfig
func loadImageURLs(cliCfg CliConfig) ([]string, error) {
	if cliCfg.ImageURL != "" {
		log.Printf("INFO: Processing single image: %s\n", cliCfg.ImageURL)
		return []string{cliCfg.ImageURL}, nil
	}

	log.Printf("INFO: Reading image list from file: %s\n", cliCfg.InputFile)
	// Use absolute path for clarity in logs/errors
	absPath, err := filepath.Abs(cliCfg.InputFile)
	if err != nil {
		log.Printf("Warning: Could not determine absolute path for input file '%s': %v", cliCfg.InputFile, err)
		absPath = cliCfg.InputFile // Use original path if abs fails
	}

	fileContent, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("reading input file '%s': %w", absPath, err)
	}

	var inputList quay.InputImageList
	fileExt := strings.ToLower(filepath.Ext(cliCfg.InputFile))

	switch fileExt {
	case ".json":
		err = json.Unmarshal(fileContent, &inputList)
		if err != nil {
			return nil, fmt.Errorf("parsing JSON file '%s': %w", absPath, err)
		}
	case ".yaml", ".yml":
		err = yaml.Unmarshal(fileContent, &inputList)
		if err != nil {
			return nil, fmt.Errorf("parsing YAML file '%s': %w", absPath, err)
		}
	default:
		return nil, fmt.Errorf("unsupported file extension '%s' for input file '%s'. Use .json, .yaml, or .yml", fileExt, absPath)
	}

	if inputList.Images == nil {
		return []string{}, nil
	}

	log.Printf("INFO: Found %d images to process from file '%s'.\n", len(inputList.Images), absPath)
	return inputList.Images, nil
}

// runWorkerPool remains the same conceptually
func runWorkerPool(imageURLs []string, quayClient *quay.Client, numWorkers int) map[string]quay.ImageScanResult {
	// ... (implementation is unchanged) ...
	numJobs := len(imageURLs)
	jobs := make(chan string, numJobs)
	results := make(chan quay.ImageScanResult, numJobs)
	allResults := make(map[string]quay.ImageScanResult, numJobs)
	var wg sync.WaitGroup

	log.Printf("INFO: Starting %d workers...\n", numWorkers)
	for w := 1; w <= numWorkers; w++ {
		wg.Add(1)
		go worker(w, quayClient, jobs, results, &wg)
	}

	log.Println("INFO: Sending jobs to workers...")
	for _, url := range imageURLs {
		jobs <- url
	}
	close(jobs)
	log.Println("INFO: All jobs sent.")

	var collectWg sync.WaitGroup
	collectWg.Add(1)
	go func() {
		defer collectWg.Done()
		log.Println("INFO: Collecting results...")
		for i := 0; i < numJobs; i++ {
			result := <-results
			allResults[result.ImageURL] = result
		}
		log.Println("INFO: All results collected.")
	}()

	log.Println("INFO: Waiting for workers to complete...")
	wg.Wait()
	log.Println("INFO: All workers finished processing.")

	collectWg.Wait()
	close(results)

	return allResults
}

// worker remains the same
func worker(id int, quayClient *quay.Client, jobs <-chan string, results chan<- quay.ImageScanResult, wg *sync.WaitGroup) {
	// ... (implementation is unchanged) ...
	defer wg.Done()
	for imageURL := range jobs {
		log.Printf("INFO: [Worker %d] Processing image: %s\n", id, imageURL)
		result := processImage(imageURL, quayClient)
		results <- result
		log.Printf("INFO: [Worker %d] Finished image: %s (Error: %t)\n", id, imageURL, result.Error != "")
	}
	log.Printf("INFO: [Worker %d] Exiting.\n", id)
}

// processImage remains the same
func processImage(imageURL string, quayClient *quay.Client) quay.ImageScanResult {
	// ... (implementation is unchanged) ...
	result := quay.ImageScanResult{ImageURL: imageURL}

	repo, tag, err := parseImageURL(imageURL)
	if err != nil {
		result.Error = fmt.Sprintf("Parsing URL failed: %v", err)
		return result
	}

	imageID, err := quayClient.GetImageID(repo, tag)
	if err != nil {
		result.Error = fmt.Sprintf("Getting image ID failed: %v", err)
		return result
	}
	if imageID == "" {
		// This case should be handled by GetImageID returning an error now
		result.Error = fmt.Sprintf("Could not find image ID for tag '%s' (tag might not exist or image details missing)", tag)
		return result
	}

	report, err := quayClient.GetVulnerabilities(repo, imageID)
	if err != nil {
		result.Error = fmt.Sprintf("Getting vulnerabilities failed: %v", err)
		if report != nil {
			result.Report = report
		}
		return result
	}

	result.Report = report
	return result
}

// parseImageURL remains the same
func parseImageURL(imageURL string) (repo string, tag string, err error) {
	// ... (implementation is unchanged) ...
	if !strings.HasPrefix(imageURL, "quay.io/") {
		err = fmt.Errorf("image URL must start with 'quay.io/'")
		return
	}
	trimmedURL := strings.TrimPrefix(imageURL, "quay.io/")
	parts := strings.SplitN(trimmedURL, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		err = fmt.Errorf("invalid image URL format. Expected 'quay.io/repository/name:tag', got '%s'", imageURL)
		return
	}
	repo = parts[0]
	tag = parts[1]
	if strings.Contains(repo, "..") || strings.Contains(tag, "..") || strings.Contains(tag, "/") {
		err = fmt.Errorf("invalid characters in repository or tag")
		return
	}
	return repo, tag, nil
}

// outputResults remains the same
func outputResults(results map[string]quay.ImageScanResult, format string, writer io.Writer) error {
	// ... (implementation is unchanged) ...
	switch format {
	case "json":
		err := formatter.FormatJSON(writer, results)
		if err != nil {
			return fmt.Errorf("formatting JSON output: %w", err)
		}
	case "human":
		formatter.FormatHumanReadable(writer, results)
	default:
		return fmt.Errorf("internal error: unknown output format '%s'", format)
	}
	return nil
}
