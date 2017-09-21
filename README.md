# Easily convert PEM files to Java Keystore

[![Build Status](https://travis-ci.org/jimmidyson/pemtokeystore.svg?branch=master)](https://travis-ci.org/jimmidyson/pemtokeystore)
[![Go Report Card](https://goreportcard.com/badge/github.com/jimmidyson/pemtokeystore)](https://goreportcard.com/report/github.com/jimmidyson/pemtokeystore)
[![GoDoc](https://godoc.org/github.com/jimmidyson/pemtokeystore?status.svg)](https://godoc.org/github.com/jimmidyson/pemtokeystore)
[![license](https://img.shields.io/github/license/jimmidyson/pemtokeystore.svg)](https://github.com/jimmidyson/pemtokeystore)

## Installation

    go get github.com/syndesisio/pemtokeystore/cmd/pemtokeystore

## Usage
    Usage of pemtokeystore:
      -ca-file path
            PEM-encoded CA certificate file path(s) - repeat for multiple files
      -cert-file alias=path
            PEM-encoded certificate file(s) in the format alias=path - repeat for multiple files
      -key-file alias=path
            PEM-encoded private key file(s) in the format alias=path - repeat for multiple files
      -keystore path
            path to keystore
      -keystore-password password
            keystore password

## Example
```bash
$ pemtokeystore -keystore my.ks -keystore-password changeit \
                -ca-file ca-root.pem -ca-file ca-signer.pem \
                -cert-file myserver=server.pem -key-file myserver=key.pem
```

### License
This project is [Apache Licensed](LICENSE)
