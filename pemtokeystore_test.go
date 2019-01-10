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

package pemtokeystore_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/pavel-v-chernykh/keystore-go"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"sync"

	"strings"

	"time"

	"github.com/jimmidyson/pemtokeystore"
)

const (
	rootCAFile                   = "root-ca"
	serverFromRootCAFile         = "server-from-root"
	serverFromIntermediateCAFile = "server-from-intermediate"
)

var (
	testKeystore = filepath.Join("testdata", "test.ks")

	serverCerts = [][]string{
		[]string{serverFromRootCAFile, rootCAFile},
		[]string{serverFromIntermediateCAFile, rootCAFile},
	}
)

func certFile(name string) string {
	return filepath.Join("testdata", name+".pem")
}

func keyFile(name string) string {
	return filepath.Join("testdata", name+"-key.pem")
}

func startTLSServer(certs ...string) (*httptest.Server, error) {
	certChainBytes, err := ioutil.ReadFile(certFile(certs[0] + "-bundle"))
	if err != nil {
		return nil, err
	}
	keyBytes, err := ioutil.ReadFile(keyFile(certs[0]))
	if err != nil {
		return nil, err
	}
	serverCert, err := tls.X509KeyPair(certChainBytes, keyBytes)
	if err != nil {
		return nil, err
	}

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, client")
	}))

	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}
	ts.StartTLS()

	err = validateServerCert(certFile(certs[len(certs)-1]), ts.URL)
	if err != nil {
		ts.Close()
		return nil, err
	}

	return ts, nil
}

func validateServerCert(caCertFile, url string) error {
	caCert, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		return err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
	}
	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	resp.Body.Close()

	return nil
}

func validateKeystoreWithKeytool(t *testing.T, path string) error {
	keystore := testKeystore
	if path != "" {
		keystore = path
	}
	keytool, err := exec.LookPath("keytool")
	if err == nil {
		cmd := exec.Command(keytool, "-list", "-keystore", keystore, "-storepass", pemtokeystore.DefaultKeystorePassword)
		out, err := cmd.CombinedOutput()
		t.Log(string(out))
		return err
	}
	return nil
}

func TestCACertConversion(t *testing.T) {
	contents, err := ioutil.ReadFile(certFile(serverFromIntermediateCAFile))
	if err != nil {
		t.Fatal(err)
	}
	converter := pemtokeystore.CertConverter{
		CACerts:                []pemtokeystore.CertReader{
			&pemtokeystore.ByteCert{
				Cert: contents,
				Name: "server-from-intermediate",
			},
		},
	}
	k, err := converter.ConvertCertsToKeystore()
	if err != nil {
		t.Fatal(err)
	}
	truststore, ok := k["localhost"].(*keystore.TrustedCertificateEntry)
	if !ok {
		t.Fatalf("Converted keystore does not contain a trusted certificate entry %v", truststore)
	}
	if truststore.Certificate.Type != "X509" {
		t.Fatalf("Parsed certificate is invalid")
	}
}

func TestJavaClientKeystore(t *testing.T) {
	javac, err := exec.LookPath("javac")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(javac, "testdata/Client.java")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Log(string(out))
		t.Fatal(err)
	}

	java, err := exec.LookPath("java")
	if err != nil {
		t.Fatal(err)
	}

	for _, s := range serverCerts {
		func() {
			ts, err := startTLSServer(s...)
			if err != nil {
				t.Error(err)
				return
			}
			defer ts.Close()

			opts := pemtokeystore.Options{
				CACertFiles:      []string{certFile(rootCAFile)},
				KeystorePath: testKeystore,
			}
			defer os.Remove(testKeystore)
			if err = pemtokeystore.CreateKeystore(opts); err != nil {
				t.Error(err)
				return
			}
			if err = validateKeystoreWithKeytool(t, ""); err != nil {
				t.Error(err)
				return
			}

			cmd := exec.Command(java, "-cp", "testdata", "Client", testKeystore, ts.URL)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Log(string(out))
				t.Error(err)
				return
			}
		}()
	}
}

func TestJavaServerKeystore(t *testing.T) {
	javac, err := exec.LookPath("javac")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(javac, "testdata/Server.java")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Log(string(out))
		t.Fatal(err)
	}

	java, err := exec.LookPath("java")
	if err != nil {
		t.Fatal(err)
	}

	for _, s := range serverCerts {
		func() {
			opts := pemtokeystore.Options{
				PrivateKeyFiles:  map[string]string{"server": keyFile(s[0])},
				CertFiles:        map[string]string{"server": certFile(s[0] + "-bundle")},
				KeystorePath: testKeystore,
			}
			//defer os.Remove(testKeystore)
			if err = pemtokeystore.CreateKeystore(opts); err != nil {
				t.Error(err)
				return
			}
			if err = validateKeystoreWithKeytool(t, ""); err != nil {
				t.Error(err)
				return
			}

			var wg sync.WaitGroup
			wg.Add(1)
			cmd := exec.Command(java, "-cp", "testdata", "Server", testKeystore, "12345")
			out := bytes.Buffer{}
			cmd.Stdout = &out
			cmd.Stderr = &out
			err = cmd.Start()
			if err != nil {
				t.Error(err)
				return
			}

			go func() {
				defer wg.Done()
				cmd.Wait()
			}()

			// Give the Java server time to start up.
			<-time.After(1 * time.Second)

			err = validateServerCert(certFile(s[len(s)-1]), "https://localhost:12345")
			cmd.Process.Kill()
			if err != nil {
				t.Error(err)
			}

			wg.Wait()
			o := out.String()
			if len(strings.TrimSpace(o)) > 0 {
				t.Log(o)
			}
		}()
	}
}
