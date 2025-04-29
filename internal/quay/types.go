package quay

// TagInfo, SecurityReport, SecurityData, Layer, Feature, Vulnerability structs go here...
// (Copied from previous example if not in a separate types.go)
// TagInfo represents the response from the tag endpoint
type TagInfo struct {
	Tags []struct {
		Name           string `json:"name"`
		ManifestDigest string `json:"manifest_digest"` // Prioritize this
		ImageID        string `json:"image_id"`        // Fallback
		LastModified   string `json:"last_modified"`
		Size           int64  `json:"size"` // Added size for potential future use
	} `json:"tags"`
	Page          int  `json:"page"` // Added from observed response
	HasAdditional bool `json:"has_additional"`
}

type TagDetail struct {
	Name           string `json:"name"`
	ManifestDigest string `json:"manifest_digest"`
	ImageID        string `json:"docker_image_id"`
	LastModified   string `json:"last_modified"`
	Size           int64  `json:"size"`
	IsManifestList bool   `json:"is_manifest_list"`
	StartTs        int64  `json:"start_ts"`
	Expiration     *int64 `json:"expiration"`
	Reversion      bool   `json:"reversion"`
}
type SecurityReport struct {
	Status string       `json:"status"`
	Data   SecurityData `json:"data"`
}
type SecurityData struct {
	Layer Layer `json:"Layer"`
}
type Layer struct {
	Name             string    `json:"Name"`
	NamespaceName    string    `json:"NamespaceName"`
	IndexedByVersion int       `json:"IndexedByVersion"`
	Features         []Feature `json:"Features"`
}
type Feature struct {
	Name            string          `json:"Name"`
	Version         string          `json:"Version"`
	VersionFormat   string          `json:"VersionFormat"`
	NamespaceName   string          `json:"NamespaceName"`
	AddedBy         string          `json:"AddedBy"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}
type Vulnerability struct {
	Name          string                 `json:"Name"`
	NamespaceName string                 `json:"NamespaceName"`
	Description   string                 `json:"Description"`
	Link          string                 `json:"Link"`
	Severity      string                 `json:"Severity"`
	Metadata      map[string]interface{} `json:"Metadata"`
	FixedBy       string                 `json:"FixedBy"`
	FixedIn       []Feature              `json:"FixedIn,omitempty"`
}

// InputImageList defines the structure for the input file (JSON/YAML)
type InputImageList struct {
	Images []string `json:"images" yaml:"images"`
}

// ImageScanResult holds the outcome of scanning a single image
type ImageScanResult struct {
	ImageURL string          `json:"imageUrl"`
	Report   *SecurityReport `json:"report,omitempty"` // Pointer, nil if error or not scanned
	Error    string          `json:"error,omitempty"`  // Store error as string for easy JSON marshalling
}
