// internal/quay/client.go
package quay

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	// "net/http/httputil" // Keep if needed for debugging
	"net/url"
	"strings"
	"time"
	// "os" // No longer needed here
)

// --- REMOVE Constants ---
// const defaultAPIBaseURL = "https://quay.io/api/v1/"
// const defaultTimeout = 15 * time.Second
// const userAgent = "golang-quay-vuln-scanner/1.0"

// Client manages communication with the Quay API.
type Client struct {
	BaseURL    *url.URL
	HTTPClient *http.Client
	Token      string
	UserAgent  string // Add UserAgent field
}

// NewClient creates a new Quay API client using provided configuration.
// baseURL, timeout, and userAgent should come from the loaded config.
func NewClient(baseURL string, token string, timeout time.Duration, userAgent string) (*Client, error) {
	// Validate inputs that MUST be provided
	if baseURL == "" {
		return nil, fmt.Errorf("quay API base URL cannot be empty")
	}
	// Ensure timeout is somewhat reasonable (handled better in config loading now)
	if timeout <= 0 {
		timeout = 10 * time.Second // Fallback if somehow 0 is passed
		log.Printf("WARN: Received invalid timeout <= 0, using fallback: %v", timeout)
	}

	parsedBaseURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL '%s': %w", baseURL, err)
	}
	// Ensure trailing slash for correct relative path resolution
	if !strings.HasSuffix(parsedBaseURL.Path, "/") {
		parsedBaseURL.Path += "/"
	}

	// Use default user agent if none provided (though config should provide one)
	if userAgent == "" {
		userAgent = "golang-quay-scanner/unknown-version"
		log.Println("WARN: No User-Agent provided to Quay client, using default.")
	}

	return &Client{
		BaseURL: parsedBaseURL,
		HTTPClient: &http.Client{
			Timeout: timeout, // Use the provided timeout
		},
		Token:     token,
		UserAgent: userAgent, // Store the provided UserAgent
	}, nil
}

// doRequest performs an HTTP request and decodes the JSON response.
func (c *Client) doRequest(method, path string, target interface{}) error {
	relURL, err := url.Parse(path)
	if err != nil {
		return fmt.Errorf("invalid API path %q: %w", path, err)
	}
	fullURL := c.BaseURL.ResolveReference(relURL)

	req, err := http.NewRequest(method, fullURL.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create request for %s: %w", fullURL, err)
	}
	req.Header.Set("User-Agent", c.UserAgent) // Use the UserAgent from the client struct

	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		// Add URL to context for network errors
		return fmt.Errorf("failed to execute request to %s: %w", fullURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Try to read some of the body for context, but don't fail if read fails
		bodyBytes := make([]byte, 512)
		n, _ := resp.Body.Read(bodyBytes)
		errorBody := string(bodyBytes[:n])
		return fmt.Errorf("API request to %s failed with status %s. Body snippet: %s", fullURL, resp.Status, errorBody)
	}

	if target != nil {
		if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
			return fmt.Errorf("failed to decode JSON response from %s: %w", fullURL, err)
		}
	}
	return nil
}

// GetImageID fetches the image digest (SHA) for a given repo and tag.
// ... (no changes needed in GetImageID itself) ...
func (c *Client) GetImageID(repo, tag string) (string, error) {
	// ... existing implementation ...
	path := fmt.Sprintf("repository/%s/tag/%s", repo, url.PathEscape(tag))
	var tagDetail TagDetail
	err := c.doRequest("GET", path, &tagDetail)
	if err != nil {
		// Check for 404 specifically, might indicate tag not found
		if strings.Contains(err.Error(), "status 404") {
			return "", fmt.Errorf("tag '%s' not found in repository '%s' (or repository is private/inaccessible)", tag, repo)
		}
		return "", fmt.Errorf("failed to get tag details for %s:%s: %w", repo, tag, err)
	}

	if tagDetail.ManifestDigest != "" {
		digest := strings.TrimPrefix(tagDetail.ManifestDigest, "sha256:")
		return digest, nil
	}
	if tagDetail.ImageID != "" {
		digest := strings.TrimPrefix(tagDetail.ImageID, "sha256:")
		return digest, nil
	}
	return "", fmt.Errorf("could not determine image digest for tag '%s' (no manifest_digest or docker_image_id found)", tag)
}

// GetVulnerabilities fetches the security report for a given repo and image digest.
// ... (no changes needed in GetVulnerabilities itself) ...
func (c *Client) GetVulnerabilities(repo, imageDigest string) (*SecurityReport, error) {
	// ... existing implementation ...
	path := fmt.Sprintf("repository/%s/image/%s/security?vulnerabilities=true", repo, imageDigest)
	var report SecurityReport
	err := c.doRequest("GET", path, &report)
	if err != nil {
		// Check for 404 specifically, might indicate image digest not found or no scan data
		if strings.Contains(err.Error(), "status 404") {
			return nil, fmt.Errorf("security information not found for image digest '%s' in repository '%s' (image may not exist or scan data unavailable)", imageDigest, repo)
		}
		return nil, fmt.Errorf("failed to get security info for image %s: %w", imageDigest, err)
	}
	if report.Status != "scanned" {
		log.Printf("WARN: Scan status for %s/%s is '%s'. Vulnerability data may be incomplete or unavailable.", repo, imageDigest, report.Status)
	}
	return &report, nil
}
