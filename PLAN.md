# Image security querying tool

## Steps
1.  **Parse CLI arguments:** Use the standard `flag` package to get the image URL and output format.
2.  **Validate Input:** Ensure the image URL points to `quay.io` and the format is either `json` or `human`.
3.  **Extract Repository and Tag:** Parse the image URL to get the repository path (e.g., `coreos/etcd`) and the tag (e.g., `v3.5.0`).
4.  **Query Quay API (Step 1 - Get Image ID):** The security API endpoint needs the *image digest* (SHA), not the tag. We first need to query the tag endpoint to find the corresponding image digest.
    *   Endpoint: `GET /api/v1/repository/{repository}/tag/{tag}/images`
5.  **Query Quay API (Step 2 - Get Vulnerabilities):** Use the obtained image digest to query the security endpoint.
    *   Endpoint: `GET /api/v1/repository/{repository}/image/{imageid}/security?vulnerabilities=true`
6.  **Handle API Response:** Decode the JSON response from the security endpoint.
7.  **Format Output:** Print the results either as raw JSON or in a human-readable table format.
8.  **Error Handling:** Implement robust error handling for network issues, API errors, invalid input, etc.

# Scan multiple files

**Changes:**

1.  **Input:** Accept a `-file` flag pointing to a JSON or YAML file containing a list of image URLs. Mutually exclusive with `-image`.
2.  **Concurrency:** Implement a worker pool using goroutines and channels.
    *   `jobs` channel: Sends image URLs to workers.
    *   `results` channel: Receives processing results (success or error) from workers.
    *   Configurable number of workers (`-workers` flag).
3.  **Data Structures:**
    *   Struct to parse the input file (`InputImageList`).
    *   Struct to hold the result for each image (`ImageScanResult`).
4.  **Output:** Adapt JSON and human-readable formats to show results for all processed images.
5.  **Error Handling:** Report errors for individual images without stopping the processing of others.


# Create Docker Image

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
