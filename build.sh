#!/usr/bin/env bash
go mod tidy

# 2.  **Build:** Build the executable from the `cmd` directory.
# This creates the `quay-scanner` executable in the project root.
go build -v -o quay-scanner ./cmd/quay-scanner

# 3.  **Run:** Use it the same way as before.
./quay-scanner -h
# ./quay-scanner -image quay.io/coreos/etcd:v3.5.0 -format human
# ./quay-scanner -image quay.io/prometheus/prometheus:v2.30.0 -format json -verbose
