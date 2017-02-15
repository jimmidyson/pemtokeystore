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

	keystore "github.com/pavel-v-chernykh/keystore-go"
)

const (
	DefaultKeystorePassword = "changeit"
)

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

func CreateKeystore(opts Options) error {
	if len(opts.KeystorePath) == 0 {
		return fmt.Errorf("Missing keystore path")
	}

	keystorePassword := []byte(opts.KeystorePassword)
	if len(keystorePassword) == 0 {
		keystorePassword = []byte(DefaultKeystorePassword)
	}

	var ks keystore.KeyStore
	if len(opts.SourceKeystorePath) > 0 {
		sourceKeystorePassword := []byte(opts.SourceKeystorePassword)
		if len(keystorePassword) == 0 {
			sourceKeystorePassword = []byte(DefaultKeystorePassword)
		}

		sourceKs, err := readKeyStore(opts.SourceKeystorePath, sourceKeystorePassword)
		if err != nil {
			return err
		}

		ks = sourceKs
	} else {
		sourceKs, err := readKeyStore(opts.KeystorePath, keystorePassword)
		if err != nil && !os.IsNotExist(err) {
			return err
		}

		ks = sourceKs
	}

	for _, caFile := range opts.CACertFiles {
		caCerts, err := readCACertsFromFile(caFile)
		if err != nil {
			return err
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
			return err
		}

		for _, file := range files {
			if file.IsDir() {
				continue
			}
			caCerts, err := readCACertsFromFile(filepath.Join(caDir, file.Name()))
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

	for alias, file := range opts.PrivateKeyFiles {
		priv, err := privateKeyFromFile(file, keystorePassword)
		if err != nil {
			return err
		}

		certs, err := certsFromFile(opts.CertFiles[alias])
		if err != nil {
			return err
		}
		ks[alias] = &keystore.PrivateKeyEntry{
			Entry:     keystore.Entry{CreationDate: time.Now()},
			PrivKey:   priv,
			CertChain: certs,
		}
	}

	return writeKeyStore(ks, opts.KeystorePath, keystorePassword)
}

func readCACertsFromFile(caFile string) (map[string]keystore.Certificate, error) {
	certs, err := certsFromFile(caFile)
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
				return nil, fmt.Errorf("missing cn in CA certificate subject: %v", ca.Subject)
			}

			alias := strings.Replace(strings.ToLower(cn), " ", "", -1)
			aliasCertMap[alias] = cert
		}
	}
	return aliasCertMap, nil
}

func privateKeyFromFile(file string, password []byte) ([]byte, error) {
	pkbs, err := pemFileToBlocks(file)
	if err != nil {
		return nil, err
	}
	if len(pkbs) != 1 {
		return nil, fmt.Errorf("failed to single PEM block from file %s", file)
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

func certsFromFile(file string) ([]keystore.Certificate, error) {
	if len(file) == 0 {
		return nil, nil
	}

	cbs, err := pemFileToBlocks(file)
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

func pemFileToBlocks(path string) ([]*pem.Block, error) {
	raw, err := ioutil.ReadFile(path)
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
			return nil, fmt.Errorf("failed to decode any PEM blocks from %s", path)
		}
		pemBlocks = append(pemBlocks, current)
		if len(raw) == 0 {
			break
		}
	}
	return pemBlocks, nil
}

func writeKeyStore(ks keystore.KeyStore, path string, passphrase []byte) error {
	// Let's do this atomically (temp + rename) in case anything is watching (inotify?) on
	// the keystore itself.
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	dir, filename := filepath.Split(absPath)
	tempFile, err := ioutil.TempFile(dir, "."+filename)
	if err != nil {
		return err
	}
	err = keystore.Encode(tempFile, ks, passphrase)
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
