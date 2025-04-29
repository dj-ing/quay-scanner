package formatter

import (
	"encoding/json"
	"fmt"
	"io"
	"sort" // To print results in a consistent order
	"strings"
	"text/tabwriter"

	"quay-scanner/internal/quay" // Adjust import path if needed
)

// FormatJSON outputs the aggregated results as indented JSON.
// Input is expected to be map[string]quay.ImageScanResult
func FormatJSON(w io.Writer, results map[string]quay.ImageScanResult) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		return fmt.Errorf("failed to marshal results to JSON: %w", err)
	}
	return nil
}

// FormatHumanReadable outputs the results for multiple images.
func FormatHumanReadable(w io.Writer, results map[string]quay.ImageScanResult) {
	// Sort image URLs for consistent output order
	urls := make([]string, 0, len(results))
	for k := range results {
		urls = append(urls, k)
	}
	sort.Strings(urls)

	firstImage := true
	for _, imageURL := range urls {
		result := results[imageURL]

		if !firstImage {
			fmt.Fprintln(w, "\n"+strings.Repeat("=", 80)) // Separator
		}
		firstImage = false

		fmt.Fprintf(w, "Scan Report for: %s\n", result.ImageURL)
		fmt.Fprintln(w, strings.Repeat("-", len(result.ImageURL)+17)) // Underline

		if result.Error != "" {
			fmt.Fprintf(w, "  Error: %s\n", result.Error)
			continue // Move to the next image
		}

		if result.Report == nil {
			fmt.Fprintln(w, "  Error: No report data available (internal error).")
			continue
		}

		fmt.Fprintf(w, "  Scan Status: %s\n", result.Report.Status)

		if result.Report.Status != "scanned" {
			fmt.Fprintln(w, "  No detailed vulnerability data available (scan may be queued or failed).")
			continue
		}

		if result.Report.Data.Layer.Features == nil || len(result.Report.Data.Layer.Features) == 0 {
			fmt.Fprintln(w, "  No features with vulnerabilities found in the scan data.")
			continue
		}

		vulnerabilitiesFound := false
		// Use tabwriter for aligned columns
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0) // Indent using spaces in Fprintf
		fmt.Fprintln(tw, "  CVE\tSeverity\tPackage\tVersion\tFixed By\tLink")
		fmt.Fprintln(tw, "  ---\t--------\t-------\t-------\t--------\t----")

		for _, feature := range result.Report.Data.Layer.Features {
			if len(feature.Vulnerabilities) > 0 {
				vulnerabilitiesFound = true
				for _, vuln := range feature.Vulnerabilities {
					fixedBy := vuln.FixedBy
					if fixedBy == "" {
						fixedBy = "N/A"
					}
					// Indent each line of the table
					fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n",
						vuln.Name,
						vuln.Severity,
						feature.Name,
						feature.Version,
						fixedBy,
						vuln.Link,
					)
				}
			}
		}

		if !vulnerabilitiesFound {
			fmt.Fprintln(tw) // Flush preamble if no vulns found
			tw.Flush()
			fmt.Fprintln(w, "\n  No vulnerabilities found for this image.")
		} else {
			fmt.Fprintln(tw) // Add a newline at the end
			tw.Flush()       // Flush the buffer to print the table
		}
	}
}
