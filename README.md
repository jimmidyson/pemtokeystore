# Easily convert PEM files to Java Keystore

## Installation

    go get github.com/jimmidyson/pemtokeystore/cmd/pemtokeystore

## Usage

    Usage of /tmp/go-build766074200/command-line-arguments/_obj/exe/main:
      -ca-cert-file value
            PEM-encoded CA certificate file(s) - repeat for multiple files
      -cert-file alias=path
            PEM-encoded certificate file(s) in the format alias=path - repeat for multiple files
      -key-file alias=path
            PEM-encoded private key file(s) in the format alias=path - repeat for multiple files
      -keystore string
            path to keystore
      -keystore-password string
            keystore password