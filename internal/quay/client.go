// internal/quay/client.go
package quay

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http" // Keep for debugging if needed
	"net/url"
	"strings"
	"time"
)

const (
	defaultAPIBaseURL = "https://quay.io/api/v1/" // Keep trailing slash
	defaultTimeout    = 15 * time.Second
	userAgent         = "golang-quay-vuln-scanner/1.0"
)

// Client manages communication with the Quay API.
type Client struct {
	BaseURL    *url.URL
	HTTPClient *http.Client
	Token      string
}

// NewClient creates a new Quay API client.
func NewClient(baseURL string, token string) (*Client, error) {
	if baseURL == "" {
		baseURL = defaultAPIBaseURL
	}
	parsedBaseURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}
	if !strings.HasSuffix(parsedBaseURL.Path, "/") {
		parsedBaseURL.Path += "/"
	}

	return &Client{
		BaseURL: parsedBaseURL,
		HTTPClient: &http.Client{
			Timeout: defaultTimeout,
		},
		Token: token,
	}, nil
}

// doRequest performs an HTTP request and decodes the JSON response.
func (c *Client) doRequest(method, path string, target interface{}) error {
	relURL, err := url.Parse(path)
	if err != nil {
		return fmt.Errorf("invalid API path %q: %w", path, err)
	}
	fullURL := c.BaseURL.ResolveReference(relURL)

	// Reduced logging noise, keep URL for context on error
	// log.Printf("DEBUG: Constructed Full URL: %s", fullURL.String())

	req, err := http.NewRequest(method, fullURL.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create request for %s: %w", fullURL, err)
	}
	req.Header.Set("User-Agent", userAgent)

	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
		// log.Println("DEBUG: Added Authorization header.") // Reduce noise
	} else {
		// log.Println("DEBUG: No token provided, making anonymous request.") // Reduce noise
	}

	// Optional: Keep request dump for deep debugging if needed
	// dump, dumpErr := httputil.DumpRequestOut(req, true)
	// if dumpErr == nil {
	//  log.Printf("DEBUG: --- Outgoing Request Dump ---\n%s\n------------------------------", string(dump))
	// }

	// log.Printf("DEBUG: Executing request to %s", fullURL) // Reduce noise

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request for %s: %w", fullURL, err)
	}
	defer resp.Body.Close()

	// log.Printf("DEBUG: Received response status: %s for %s", resp.Status, fullURL) // Reduce noise

	if resp.StatusCode != http.StatusOK {
		bodyBytes := make([]byte, 512)
		n, _ := resp.Body.Read(bodyBytes)
		errorBody := string(bodyBytes[:n])
		// log.Printf("DEBUG: Non-OK Response Body Snippet: %s", errorBody) // Reduce noise
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
func (c *Client) GetImageID(repo, tag string) (string, error) {
	path := fmt.Sprintf("repository/%s/tag/%s", repo, url.PathEscape(tag))
	var tagDetail TagDetail
	err := c.doRequest("GET", path, &tagDetail)
	if err != nil {
		return "", fmt.Errorf("failed to get tag details for %s:%s: %w", repo, tag, err)
	}

	if tagDetail.ManifestDigest != "" {
		// log.Printf("DEBUG: Found Manifest Digest: %s\n", tagDetail.ManifestDigest) // Reduce noise
		digest := strings.TrimPrefix(tagDetail.ManifestDigest, "sha256:")
		return digest, nil
	}
	if tagDetail.ImageID != "" {
		// log.Printf("DEBUG: Using Image ID (docker_image_id) as fallback: %s\n", tagDetail.ImageID) // Reduce noise
		digest := strings.TrimPrefix(tagDetail.ImageID, "sha256:")
		return digest, nil
	}
	return "", fmt.Errorf("could not determine image digest for tag '%s'", tag)
}

// GetVulnerabilities fetches the security report for a given repo and image digest.
func (c *Client) GetVulnerabilities(repo, imageDigest string) (*SecurityReport, error) {
	path := fmt.Sprintf("repository/%s/image/%s/security?vulnerabilities=true", repo, imageDigest)
	var report SecurityReport
	err := c.doRequest("GET", path, &report)
	if err != nil {
		return nil, fmt.Errorf("failed to get security info for image %s: %w", imageDigest, err)
	}
	if report.Status != "scanned" {
		log.Printf("WARN: Scan status for %s/%s is '%s'. Vulnerability data may be incomplete or unavailable.", repo, imageDigest, report.Status)
	}
	return &report, nil
}
