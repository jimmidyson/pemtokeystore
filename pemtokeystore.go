//  Copyright 2016 Red Hat, Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package pemtokeystore

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pavel-v-chernykh/keystore-go"
)

const (
	DefaultKeystorePassword = "changeit"
)

type CertConverter struct {
	PrivateKeys                               map[string]CertReader
	Certs                                     map[string]CertReader
	CACerts                                   []CertReader
	CACertDirs                                []string
	FallbackToDescriptionWhenSubjectIsMissing bool

	SourceKeystorePath     string
	SourceKeystorePassword string
}

type Options struct {
	PrivateKeyFiles map[string]string
	CertFiles       map[string]string
	CACertFiles     []string
	CACertDirs      []string

	KeystorePath     string
	KeystorePassword string

	SourceKeystorePath     string
	SourceKeystorePassword string
}

type CertReader interface {
	Read() ([]byte, error)
	GetName() string
}

type FileCert struct {
	Path string
}

func (c *FileCert) Read() ([]byte, error) {
	raw, err := ioutil.ReadFile(c.Path)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func (c *FileCert) GetName() string {
	return c.Path
}

type ByteCert struct {
	Cert []byte
	Name string
}

func (c *ByteCert) Read() ([]byte, error) {
	return c.Cert, nil
}

func (c *ByteCert) GetName() string {
	return c.Name
}

func CreateKeystore(opts Options) error {
	optsv2 := CertConverter{
		CACertDirs:             opts.CACertDirs,
		SourceKeystorePath:     opts.SourceKeystorePath,
		SourceKeystorePassword: opts.SourceKeystorePassword,
	}

	if len(opts.PrivateKeyFiles) > 0 {
		optsv2.PrivateKeys = map[string]CertReader{}
		for a, f := range opts.PrivateKeyFiles {
			optsv2.PrivateKeys[a] = &FileCert{Path: f}
		}
	}

	if len(opts.CertFiles) > 0 {
		optsv2.Certs = map[string]CertReader{}
		for a, f := range opts.CertFiles {
			optsv2.Certs[a] = &FileCert{Path: f}
		}
	}

	if len(opts.CACertFiles) > 0 {
		optsv2.CACerts = []CertReader{}
		for _, f := range opts.CACertFiles {
			optsv2.CACerts = append(optsv2.CACerts, &FileCert{Path: f})
		}
	}

	ks, err := optsv2.ConvertCertsToKeystore()
	if err != nil {
		return err
	}

	return WriteKeyStore(ks, opts.KeystorePath, opts.KeystorePassword)
}


func (opts *CertConverter) ConvertCertsToKeystore() (keystore.KeyStore, error) {

	var ks keystore.KeyStore
	if len(opts.SourceKeystorePath) > 0 {
		sourceKeystorePassword := []byte(opts.SourceKeystorePassword)
		if len(sourceKeystorePassword) == 0 {
			sourceKeystorePassword = []byte(DefaultKeystorePassword)
		}

		sourceKs, err := readKeyStore(opts.SourceKeystorePath, sourceKeystorePassword)
		if err != nil {
			return nil, err
		}

		ks = sourceKs
	} else {
		ks = keystore.KeyStore{}
	}

	for _, caFile := range opts.CACerts {
		caCerts, err := opts.parseCerts(caFile)
		if err != nil {
			return nil, err
		}

		for alias, cert := range caCerts {
			ks[alias] = &keystore.TrustedCertificateEntry{
				Entry:       keystore.Entry{CreationDate: time.Now()},
				Certificate: cert,
			}
		}
	}

	for _, caDir := range opts.CACertDirs {
		files, err := ioutil.ReadDir(caDir)
		if err != nil {
			return nil, err
		}

		for _, file := range files {
			if file.IsDir() {
				continue
			}
			caCerts, err := opts.parseCerts(&FileCert{filepath.Join(caDir, file.Name())})
			if err != nil {
				continue
			}

			for alias, cert := range caCerts {
				ks[alias] = &keystore.TrustedCertificateEntry{
					Entry:       keystore.Entry{CreationDate: time.Now()},
					Certificate: cert,
				}
			}
		}
	}

	for alias, file := range opts.PrivateKeys {
		priv, err := opts.privateKeyFromCert(file)
		if err != nil {
			return nil, err
		}

		certs, err := opts.loadCerts(opts.Certs[alias])
		if err != nil {
			return nil, err
		}
		ks[alias] = &keystore.PrivateKeyEntry{
			Entry:     keystore.Entry{CreationDate: time.Now()},
			PrivKey:   priv,
			CertChain: certs,
		}
	}

	return ks, nil
}

func (opts *CertConverter) parseCerts(certReader CertReader) (map[string]keystore.Certificate, error) {
	certs, err := opts.loadCerts(certReader)
	if err != nil {
		return nil, err
	}

	aliasCertMap := map[string]keystore.Certificate{}
	for _, cert := range certs {
		parsed, err := x509.ParseCertificates(cert.Content)
		if err != nil {
			return nil, err
		}

		if len(parsed) < 1 {
			return nil, fmt.Errorf("could not decode CA certificate")
		}

		for _, ca := range parsed {
			cn := ca.Subject.CommonName
			if len(cn) == 0 {
				if opts.FallbackToDescriptionWhenSubjectIsMissing {
					cn = certReader.GetName()
				} else {
					return nil, fmt.Errorf("missing cn in CA certificate subject: %v", ca.Subject)
				}
			}

			alias := strings.Replace(strings.ToLower(cn), " ", "", -1)
			aliasCertMap[alias] = cert
		}
	}
	return aliasCertMap, nil
}

func (opts *CertConverter) privateKeyFromCert(certReader CertReader) ([]byte, error) {
	pkbs, err := opts.pemToBlocks(certReader)
	if err != nil {
		return nil, err
	}
	if len(pkbs) != 1 {
		return nil, fmt.Errorf("failed to get single PEM block from cert %s", certReader.GetName())
	}

	var pk interface{}
	pkb := pkbs[0]
	switch pkb.Type {
	case "RSA PRIVATE KEY":
		pk, err = x509.ParsePKCS1PrivateKey(pkb.Bytes)
	case "EC PRIVATE KEY":
		pk, err = x509.ParseECPrivateKey(pkb.Bytes)
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", pkb.Type)
	}

	if err != nil {
		return nil, err
	}

	return convertPrivateKeyToPKCS8(pk)
}

func (opts *CertConverter) loadCerts(certReader CertReader) ([]keystore.Certificate, error) {
	if certReader == nil {
		return nil, nil
	}

	cbs, err := opts.pemToBlocks(certReader)
	if err != nil {
		return nil, err
	}

	var certs []keystore.Certificate
	for _, cb := range cbs {
		certs = append(certs, keystore.Certificate{
			Type:    "X509",
			Content: cb.Bytes,
		})
	}

	return certs, nil
}

func (opts *CertConverter) pemToBlocks(cert CertReader) ([]*pem.Block, error) {
	raw, err := cert.Read()
	if err != nil {
		return nil, err
	}

	var (
		pemBlocks []*pem.Block
		current   *pem.Block
	)

	for {
		current, raw = pem.Decode(raw)
		if current == nil {
			if len(pemBlocks) > 0 {
				return pemBlocks, nil
			}
			return nil, fmt.Errorf("failed to decode any PEM blocks from %s", cert.GetName())
		}
		pemBlocks = append(pemBlocks, current)
		if len(raw) == 0 {
			break
		}
	}
	return pemBlocks, nil
}

func WriteKeyStore(ks keystore.KeyStore, keystorePath string, password string) error {
	if len(keystorePath) == 0 {
		return fmt.Errorf("Missing keystore path")
	}

	keystorePassword := []byte(password)
	if len(keystorePassword) == 0 {
		keystorePassword = []byte(DefaultKeystorePassword)
	}

	// Let's do this atomically (temp + rename) in case anything is watching (inotify?) on
	// the keystore itself.
	absPath, err := filepath.Abs(keystorePath)
	if err != nil {
		return err
	}
	dir, filename := filepath.Split(absPath)
	tempFile, err := ioutil.TempFile(dir, "."+filename)
	if err != nil {
		return err
	}
	err = keystore.Encode(tempFile, ks, keystorePassword)
	tempFile.Close()
	if err != nil {
		return err
	}
	err = os.Rename(tempFile.Name(), absPath)
	if err != nil {
		os.Remove(tempFile.Name())
	}
	return err
}

func readKeyStore(filename string, password []byte) (keystore.KeyStore, error) {
	f, err := os.Open(filename)
	defer f.Close()
	if err != nil {
		return keystore.KeyStore{}, err
	}
	keyStore, err := keystore.Decode(f, password)
	if err != nil {
		return keystore.KeyStore{}, err
	}
	return keyStore, nil
}
