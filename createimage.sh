#!/usr/bin/env bash
./build.sh
docker build -t quay-scanner-app:latest .
