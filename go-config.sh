#!/bin/bash

set -e

ROOT="$PWD"
echo "Root = $ROOT"

# Download Go
echo ">>>>>>>>> Start configuration for Go  <<<<<<<<<<<"
curl -fSsOL https://golang.org/dl/go1.15.5.linux-amd64.tar.gz
tar -xzf go1.15.5.linux-amd64.tar.gz
rm -rf go1.15.5.linux-amd64.tar.gz
echo ">>>>>>>>> Go Configured successfully! :)  <<<<<<<<<<<"
