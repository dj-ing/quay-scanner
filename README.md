# image-sec

## Synopsis


## Description
tool to get securioty and vulnerabiliy infos for images from external quay registries




## **How to Build and Run:**

1.  **Save:** Save the code above as `quay-vuln-scanner.go`.
2.  **Tidy Dependencies (Optional but good practice):**
    ```bash
    go mod init quay-scanner # Or your preferred module name
    go mod tidy
    ```
3.  **Build:**
    ```bash
    go build -o quay-scanner quay-vuln-scanner.go
    ```
4.  **Run:**
    *   **Human Readable Output:**
        ```bash
        ./quay-scanner -image quay.io/coreos/etcd:v3.5.0 -format human
        # Example with another image
        ./quay-scanner -image quay.io/prometheus/prometheus:v2.30.0 -format human
        ```
    *   **JSON Output:**
        ```bash
        ./quay-scanner -image quay.io/coreos/etcd:v3.5.0 -format json
        ```
    *   **Verbose Output (for debugging):**
        ```bash
        ./quay-scanner -image quay.io/coreos/etcd:v3.5.0 -format human -verbose
        ```
    *   **Help:**
        ```bash
        ./quay-scanner -h
        ```

## **Key Features and Considerations:**

*   **Clear Separation:** The code separates API interaction, data parsing, and output formatting.
*   **Robust Error Handling:** Checks for invalid input, network errors, non-200 API responses, and JSON decoding errors. Exits with non-zero status on failure.
*   **Correct API Usage:** Uses the two-step process required by Quay (Tag -> Image ID -> Security Scan).
*   **Standard Libraries:** Relies only on Go's standard library (`flag`, `net/http`, `encoding/json`, `fmt`, `log`, `os`, `strings`, `text/tabwriter`, `time`, `net/url`, `path`).
*   **Output Formats:** Provides both machine-readable JSON and human-friendly tabular output.
*   **User Experience:** Includes usage instructions via `-h` or incorrect invocation.
*   **Timeout:** Sets a reasonable default timeout for HTTP requests.
*   **Verbose Mode:** Adds a `-verbose` flag for debugging API calls and parsing steps.
*   **URL Parsing:** Handles the specific `quay.io/repo/path:tag` format and includes basic validation. It correctly constructs the API URLs using the repository path.

This tool should effectively meet the requirements for querying Quay.io vulnerability data from the command line.
