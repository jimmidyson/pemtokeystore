package pemtokeystore

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	keystore "github.com/pavel-v-chernykh/keystore-go"
)

type Options struct {
	PrivateKeyFiles map[string]string
	CertFiles       map[string]string
	CACertFiles     []string

	KeystorePath     string
	KeystorePassword string
}

func CreateKeystore(opts Options) error {
	if len(opts.KeystorePath) == 0 {
		return fmt.Errorf("Missing keystore path")
	}

	ks := keystore.KeyStore{}

	for alias, file := range opts.PrivateKeyFiles {
		priv, err := privateKeyFromFile(file)
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

	for _, cafile := range opts.CACertFiles {
		certs, err := certsFromFile(cafile)
		if err != nil {
			return err
		}
		for _, cert := range certs {
			parsed, err := x509.ParseCertificates(cert.Content)
			if err != nil {
				return err
			}

			if len(parsed) != 1 {
				return fmt.Errorf("could not decode single CA certificate")
			}
			cn := parsed[0].Subject.CommonName
			if len(cn) == 0 {
				return fmt.Errorf("missing cn in CA certificate subject: %v", parsed[0].Subject)
			}

			ks[cn] = &keystore.TrustedCertificateEntry{
				Entry:       keystore.Entry{CreationDate: time.Now()},
				Certificate: cert,
			}
		}
	}

	return writeKeyStore(ks, opts.KeystorePath, []byte(opts.KeystorePassword))
}

func privateKeyFromFile(file string) ([]byte, error) {
	pkbs, err := pemFileToBlocks(file)
	if err != nil {
		return nil, err
	}
	if len(pkbs) != 1 {
		return nil, fmt.Errorf("failed to single PEM block from file %s", file)
	}

	return pkbs[0].Bytes, nil
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
			return pemBlocks, nil
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
