package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/jimmidyson/pemtokeystore"
)

type stringSliceFlag []string

var _ flag.Value = &stringSliceFlag{}

func (f *stringSliceFlag) String() string {
	return fmt.Sprintf("%v", *f)
}

func (f *stringSliceFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

type mapFlag map[string]string

var _ flag.Value = &mapFlag{}

func (f *mapFlag) String() string {
	return fmt.Sprintf("%v", *f)
}

func (f *mapFlag) Set(value string) error {
	var m mapFlag
	if *f == nil {
		m = (mapFlag)(map[string]string{})
	} else {
		m = *f
	}
	spl := strings.SplitN(value, "=", 2)
	if len(spl) != 2 {
		return fmt.Errorf("wrong format in %s: required format is a=b", value)
	}
	m[spl[0]] = spl[1]
	*f = m
	return nil
}

func main() {
	var opts pemtokeystore.Options

	flags := flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	flags.StringVar(&opts.KeystorePath, "keystore", "", "path to keystore")
	flags.StringVar(&opts.KeystorePassword, "keystore-password", "", "keystore password")
	flags.Var((*mapFlag)(&opts.CertFiles), "cert-file", "PEM-encoded certificate file(s) in the format `alias=path` - repeat for multiple files")
	flags.Var((*mapFlag)(&opts.PrivateKeyFiles), "key-file", "PEM-encoded private key file(s) in the format `alias=path` - repeat for multiple files")
	flags.Var((*stringSliceFlag)(&opts.CACertFiles), "ca-cert-file", "PEM-encoded CA certificate file(s) - repeat for multiple files")

	if err := flags.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to parse flags:", err)
		os.Exit(1)
	}

	if err := pemtokeystore.CreateKeystore(opts); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to create keystore:", err)
		os.Exit(2)
	}
}
