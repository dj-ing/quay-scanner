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

	"quay-scanner/internal/formatter"
	"quay-scanner/internal/quay"
)

const defaultWorkers = 5 // Default number of concurrent workers

// Config holds the application configuration derived from flags and environment.
type Config struct {
	ImageURL     string
	InputFile    string
	OutputFormat string
	Verbose      bool
	Token        string
	NumWorkers   int
}

// --- Main Execution Flow ---

func main() {
	// 1. Parse flags and initialize configuration
	cfg, err := parseFlagsAndConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		flag.Usage() // Show usage on config error
		os.Exit(1)
	}

	// 2. Setup logging based on configuration
	setupLogging(cfg.Verbose)

	// 3. Load the list of image URLs to process
	imageURLs, err := loadImageURLs(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading image URLs: %v\n", err)
		os.Exit(1)
	}
	if len(imageURLs) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No image URLs specified or found in the input file.")
		os.Exit(1)
	}
	log.Printf("INFO: Preparing to process %d image(s).\n", len(imageURLs))

	// 4. Create the Quay API client
	quayClient, err := quay.NewClient("", cfg.Token) // Use default base URL
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating Quay client: %v\n", err)
		os.Exit(1)
	}

	// 5. Run the worker pool to process images concurrently
	log.Printf("INFO: Starting vulnerability scan with %d workers...\n", cfg.NumWorkers)
	results := runWorkerPool(imageURLs, quayClient, cfg.NumWorkers)
	log.Println("INFO: Vulnerability scan finished.")

	// 6. Format and output the results
	log.Printf("INFO: Formatting output as %s...\n", cfg.OutputFormat)
	err = outputResults(results, cfg.OutputFormat, os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error formatting output: %v\n", err)
		os.Exit(1)
	}

	log.Println("INFO: Done.")
}

// --- Helper Functions ---

// parseFlagsAndConfig defines flags, parses them, validates, and returns a Config struct.
func parseFlagsAndConfig() (Config, error) {
	cfg := Config{}
	// Define flags
	flag.StringVar(&cfg.ImageURL, "image", "", "Single Quay.io image URL (mutually exclusive with -file)")
	flag.StringVar(&cfg.InputFile, "file", "", "Path to JSON or YAML file containing a list of image URLs (mutually exclusive with -image)")
	flag.StringVar(&cfg.OutputFormat, "format", "human", "Output format: 'json' or 'human'")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose logging")
	flag.StringVar(&cfg.Token, "token", "", "Quay API Bearer Token (optional, overrides QUAY_TOKEN env var)")
	flag.IntVar(&cfg.NumWorkers, "workers", defaultWorkers, "Number of concurrent workers")

	// Custom usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "\nUsage: %s [options]\n\n", path.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "Queries Quay.io for vulnerability information for one or more images.\n\n")
		fmt.Fprintf(os.Stderr, "Input:\n")
		fmt.Fprintf(os.Stderr, "  Provide either -image for a single image OR -file for multiple images.\n\n")
		fmt.Fprintf(os.Stderr, "  Input file format (JSON): \n  |  {\"images\": [\"quay.io/ns/repo:tag\", ...]}}\n\n")
		fmt.Fprintf(os.Stderr, "  Input file format (YAML): \n  |  images:\n  |  - quay.io/ns/repo:tag\n  |  - ...\n\n")
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
	}

	return cfg, nil
}

// setupLogging configures the global logger based on verbosity.
func setupLogging(verbose bool) {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if !verbose {
		log.SetOutput(io.Discard) // Disable logging if not verbose
	} else {
		log.SetOutput(os.Stderr)
		log.Println("Verbose logging enabled.")
	}
}

// loadImageURLs determines the list of image URLs from either the -image flag or the -file flag.
func loadImageURLs(cfg Config) ([]string, error) {
	if cfg.ImageURL != "" {
		log.Printf("INFO: Processing single image: %s\n", cfg.ImageURL)
		return []string{cfg.ImageURL}, nil
	}

	log.Printf("INFO: Reading image list from file: %s\n", cfg.InputFile)
	fileContent, err := os.ReadFile(cfg.InputFile)
	if err != nil {
		return nil, fmt.Errorf("reading input file '%s': %w", cfg.InputFile, err)
	}

	var inputList quay.InputImageList
	fileExt := strings.ToLower(filepath.Ext(cfg.InputFile))

	switch fileExt {
	case ".json":
		err = json.Unmarshal(fileContent, &inputList)
		if err != nil {
			return nil, fmt.Errorf("parsing JSON file '%s': %w", cfg.InputFile, err)
		}
	case ".yaml", ".yml":
		err = yaml.Unmarshal(fileContent, &inputList)
		if err != nil {
			return nil, fmt.Errorf("parsing YAML file '%s': %w", cfg.InputFile, err)
		}
	default:
		return nil, fmt.Errorf("unsupported file extension '%s'. Use .json, .yaml, or .yml", fileExt)
	}

	if inputList.Images == nil {
		// Handle case where file is valid YAML/JSON but `images` key is missing or null
		return []string{}, nil // Return empty slice, main checks for zero length
	}

	log.Printf("INFO: Found %d images to process from file.\n", len(inputList.Images))
	return inputList.Images, nil
}

// runWorkerPool sets up and executes the concurrent image processing.
func runWorkerPool(imageURLs []string, quayClient *quay.Client, numWorkers int) map[string]quay.ImageScanResult {
	numJobs := len(imageURLs)
	jobs := make(chan string, numJobs)
	results := make(chan quay.ImageScanResult, numJobs)
	allResults := make(map[string]quay.ImageScanResult, numJobs)
	var wg sync.WaitGroup

	// Start workers
	log.Printf("INFO: Starting %d workers...\n", numWorkers)
	for w := 1; w <= numWorkers; w++ {
		wg.Add(1)
		// Pass a copy of the client to each worker (Client is safe for concurrent use)
		go worker(w, quayClient, jobs, results, &wg)
	}

	// Send jobs to workers
	log.Println("INFO: Sending jobs to workers...")
	for _, url := range imageURLs {
		jobs <- url
	}
	close(jobs) // Indicate no more jobs will be sent
	log.Println("INFO: All jobs sent.")

	// Collect results
	// Start a separate goroutine to collect results to avoid blocking main
	// while waiting for workers with wg.Wait()
	var collectWg sync.WaitGroup
	collectWg.Add(1)
	go func() {
		defer collectWg.Done()
		log.Println("INFO: Collecting results...")
		for i := 0; i < numJobs; i++ {
			result := <-results
			allResults[result.ImageURL] = result
			// Optional: Add progress logging here if needed
			// log.Printf("INFO: Collected result %d/%d for %s\n", i+1, numJobs, result.ImageURL)
		}
		log.Println("INFO: All results collected.")
	}()

	// Wait for all workers to finish processing
	log.Println("INFO: Waiting for workers to complete...")
	wg.Wait()
	log.Println("INFO: All workers finished processing.")

	// Wait for the result collection goroutine to finish
	collectWg.Wait()
	close(results) // Close results channel after collection is done

	return allResults
}

// worker is the goroutine function that processes jobs from the jobs channel.
func worker(id int, quayClient *quay.Client, jobs <-chan string, results chan<- quay.ImageScanResult, wg *sync.WaitGroup) {
	defer wg.Done()
	for imageURL := range jobs {
		log.Printf("INFO: [Worker %d] Processing image: %s\n", id, imageURL)
		result := processImage(imageURL, quayClient)
		results <- result
		log.Printf("INFO: [Worker %d] Finished image: %s (Error: %t)\n", id, imageURL, result.Error != "")
	}
	log.Printf("INFO: [Worker %d] Exiting.\n", id)
}

// processImage handles the logic for scanning a single image.
func processImage(imageURL string, quayClient *quay.Client) quay.ImageScanResult {
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

	// Add check for empty imageID which can happen for non-existent tags
	if imageID == "" {
		result.Error = fmt.Sprintf("Could not find image ID for tag '%s' (tag might not exist)", tag)
		return result
	}

	report, err := quayClient.GetVulnerabilities(repo, imageID)
	if err != nil {
		result.Error = fmt.Sprintf("Getting vulnerabilities failed: %v", err)
		// Still include report status if available despite error (e.g., 404 on vuln scan)
		if report != nil {
			result.Report = report
		}
		return result
	}

	result.Report = report
	return result
}

// parseImageURL extracts repository and tag from a quay.io URL.
// (Kept separate as it's a distinct parsing task)
func parseImageURL(imageURL string) (repo string, tag string, err error) {
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
	// Basic validation against path traversal or invalid chars
	if strings.Contains(repo, "..") || strings.Contains(tag, "..") || strings.Contains(tag, "/") {
		err = fmt.Errorf("invalid characters in repository or tag")
		return
	}
	return repo, tag, nil
}

// outputResults formats and prints the collected results.
func outputResults(results map[string]quay.ImageScanResult, format string, writer io.Writer) error {
	switch format {
	case "json":
		err := formatter.FormatJSON(writer, results)
		if err != nil {
			return fmt.Errorf("formatting JSON output: %w", err)
		}
	case "human":
		// FormatHumanReadable doesn't return an error in its current signature
		formatter.FormatHumanReadable(writer, results)
	default:
		// This case should ideally be caught during flag validation
		return fmt.Errorf("internal error: unknown output format '%s'", format)
	}
	return nil
}
