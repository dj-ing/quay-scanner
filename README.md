# image-sec

## **Synopsis**

    Usage: quay-scanner [options]

    Queries Quay.io for vulnerability information for one or more images.

    Input:
      Provide either -image for a single image OR -file for multiple images.

      Input file format (JSON):
      |  {"images": ["quay.io/ns/repo:tag", ...]}}

      Input file format (YAML):
      |  images:
      |  - quay.io/ns/repo:tag
      |  - ...

    Authentication:
      Uses QUAY_TOKEN environment variable or -token flag.

    Options:
      -file string
       	Path to JSON or YAML file containing a list of image URLs (mutually exclusive with -image)
      -format string
       	Output format: 'json' or 'human' (default "human")
      -image string
       	Single Quay.io image URL (mutually exclusive with -file)
      -token string
       	Quay API Bearer Token (optional, overrides QUAY_TOKEN env var)
      -verbose
       	Enable verbose logging
      -workers int
       	Number of concurrent workers (default 5)

## **Description**

Get security and vulnerabiliy infos for images from public quay registry.

The images for which vulnerability info should be queried can be passed
as a list in a YAML or JSON file.
Alternatively, a single image can also be specified via parameter.

For each image, the vulnerability information is then queried from quay.io
and output either as JSON or in human-readable form, depending on the
specified '-format' parameter.


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
    *   **Human Readable:**
        ```bash
        # Make sure QUAY_TOKEN is set or use -token
        export QUAY_TOKEN='YOUR_TOKEN'
        ./quay-scanner -file images.yaml -format human -verbose -workers 8
        unset QUAY_TOKEN
        ```
    *   **JSON Output:**
        ```bash
        export QUAY_TOKEN='YOUR_TOKEN'
        ./quay-scanner -file images.json -format json > results.json
        unset QUAY_TOKEN
        # Inspect results.json
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


## Structure

```
    quay-scanner/
    ├── go.mod
    ├── go.sum
    ├── cmd/
    │   └── quay-scanner/
    │       └── main.go         # Main application entry point, CLI parsing, orchestration
    ├── internal/
    │   ├── quay/
    │   │   ├── client.go       # Quay API client logic (requests, response handling)
    │   │   └── types.go        # Struct definitions for Quay API responses
    │   └── formatter/
    │       └── formatter.go    # Output formatting logic (JSON, human-readable)
    └── README.md               # (Optional but recommended)
```

# Container Image

[![Docker Repository on Quay](https://quay.io/repository/djaeger62/quay-scanner/status "Docker Repository on Quay")](https://quay.io/repository/djaeger62/quay-scanner)

**Explanation:**

*   **`FROM golang:1.21-alpine AS builder`**: Starts the first stage using the official Go image (Alpine variant, which is smaller). We name this stage `builder`.
*   **`WORKDIR /app`**: Sets the current directory for subsequent commands.
*   **`COPY go.mod go.sum ./`**: Copies the module files.
*   **`RUN go mod download`**: Downloads dependencies. This layer is cached and only re-run if `go.mod` or `go.sum` changes.
*   **`COPY . .`**: Copies the rest of your source code (`internal/`, `cmd/`).
*   **`RUN CGO_ENABLED=0 ... go build ...`**: Compiles the application.
    *   `CGO_ENABLED=0`: Disables CGO, crucial for creating a static binary that doesn't rely on C libraries from the host system (important for minimal images like Alpine or scratch).
    *   `GOOS=linux`: Ensures the binary is built for Linux, even if you build the Docker image on macOS or Windows.
    *   `-ldflags="-w -s"`: Reduces binary size.
    *   `-o /quay-scanner`: Specifies the output path for the compiled binary.
    *   `./cmd/quay-scanner`: The path to your `main` package.
*   **`FROM alpine:latest`**: Starts the second, final stage using the minimal `alpine` base image.
*   **`RUN addgroup ... && adduser ...`**: Creates a dedicated, non-privileged user (`appuser`) and group (`appgroup`) for running the application. Running as non-root is a security best practice.
*   **`COPY --from=builder ...`**: Copies *only* the compiled binary from the `builder` stage into the final image's `PATH`.
*   **`RUN chmod +x ...`**: Ensures the binary has execute permissions.
*   **`USER appuser`**: Specifies that the application should run as the `appuser`.
*   **`ENTRYPOINT [...]`**: Sets the main command to run when the container starts. This is the compiled application.
*   **`CMD ["--help"]`**: Provides default arguments to the `ENTRYPOINT`. If you run `docker run <image-name>` without arguments, it will execute `/usr/local/bin/quay-scanner --help`. You can override this when running the container (e.g., `docker run <image-name> -image quay.io/repo:tag`).

**How to Build and Run:**

1.  **Build the image:**
    ```bash
    docker build -t quay-scanner-app:latest .
    ```
    (Run this command in the root directory of your project where the `Dockerfile` is located).

2.  **Run the container:**
    *   **Show help:**
        ```bash
        docker run --rm quay-scanner-app:latest
        # or explicitly
        docker run --rm quay-scanner-app:latest --help
        ```
    *   **Scan a single image (using environment variable for token):**
        ```bash
        # Replace YOUR_QUAY_TOKEN with your actual token
        docker run --rm -e QUAY_TOKEN="YOUR_QUAY_TOKEN" quay-scanner-app:latest -image quay.io/coreos/etcd:v3.5.0 -format human
        ```
    *   **Scan multiple images from a file (mount the file):**
        First, create your `images.yaml` or `images.json` file on your host machine.
        ```bash
        # Assuming images.yaml is in your current directory on the host
        docker run --rm \
          -e QUAY_TOKEN="YOUR_QUAY_TOKEN" \
          -v "$(pwd)/images.yaml:/app/images.yaml:ro" \
          quay-scanner-app:latest -file /app/images.yaml -format json -workers 10
        ```
        *   `-v "$(pwd)/images.yaml:/app/images.yaml:ro"`: Mounts your local `images.yaml` file into the container at `/app/images.yaml` in read-only (`:ro`) mode.
        *   `-file /app/images.yaml`: Tells the application inside the container where to find the input file.

This Dockerfile provides a good balance of build efficiency, small final image size, and security best practices.
