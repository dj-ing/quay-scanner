# Stage 1: Build the application
FROM golang:1.24-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Install build dependencies if any (e.g., git for private modules)
# RUN apk add --no-cache git

# Copy go module files first to leverage Docker cache
COPY go.mod go.sum ./

# Download module dependencies
# Using 'go mod download' is often faster if go.sum is up-to-date
RUN go mod download
# Alternatively, use 'go mod tidy' if you want to ensure dependencies are pruned
# RUN go mod tidy

# Copy the rest of the application source code
COPY . .

# Build the application as a static binary
# CGO_ENABLED=0 is important for static linking, especially for Alpine target
# -ldflags="-w -s" strips debug symbols and symbol table, reducing binary size
# Output the binary to a known location
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /quay-scanner ./cmd/quay-scanner

# Stage 2: Create the final minimal image
FROM alpine:latest

# Set the working directory
WORKDIR /app

# Create a non-root user and group for security
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy only the compiled binary from the builder stage
COPY --from=builder /quay-scanner /usr/local/bin/quay-scanner

# Ensure the binary is executable (usually set by 'go build', but good practice)
RUN chmod +x /usr/local/bin/quay-scanner

# Switch to the non-root user
USER appuser

# Set the entrypoint for the container
ENTRYPOINT ["/usr/local/bin/quay-scanner"]

# Set default command (e.g., show help if no args are provided)
CMD ["--help"]
