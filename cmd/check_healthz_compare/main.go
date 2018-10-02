package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/matryer/m"
)

// Nagios exit code statuses
const CRITICAL int = 2
const OK int = 0

func main() {

	var (
		endpoint = flag.String("endpoint", "", "URL of healthz endpoint to check")
		key1     = flag.String("key1", "", "key 1 in javascript notation foo.bar.baz")
		key2     = flag.String("key2", "", "key 2 in javascript notation foo.bar.baz")

		tlsClientCert       = flag.String("tls-client-cert", "", "path to certificate file used to connect to endpoint")
		tlsClientKey        = flag.String("tls-client-key", "", "path to private key file used to connect to endpoint")
		tlsClientRootCaFile = flag.String("tls-client-root-ca-file", "", "path to private certificate authority certificate used to connect to endpoint")
	)
	flag.Parse()

	if *endpoint == "" {
		log.Fatal("Set the -endpoint flag")
	}
	if *key1 == "" {
		log.Fatal("Set the -key1 flag")
	}
	if *key2 == "" {
		log.Fatal("Set the -key2 flag")
	}

	data, err := fetchHealthz(*endpoint, *tlsClientCert, *tlsClientKey, *tlsClientRootCaFile)
	if err != nil || data == nil {
		fmt.Println("ERROR: Unable to fetch healthz endpoint - ", err)
		os.Exit(CRITICAL)
	}

	key1value, ok := m.Get(data, *key1).(string)
	if !ok {
		fmt.Printf("ERROR: key %s not found or not a string", *key1)
		os.Exit(CRITICAL)
	}

	key2value, ok := m.Get(data, *key2).(string)
	if !ok {
		fmt.Printf("ERROR: key %s not found or not a string", *key2)
		os.Exit(CRITICAL)
	}

	if key1value == key2value {
		fmt.Printf("OK: %s (%s) == %s (%s)\n", *key1, key1value, *key2, key2value)
		os.Exit(OK)
	}

	fmt.Printf("CRITICAL: %s (%s) != %s (%s)\n", *key1, key1value, *key2, key2value)
	os.Exit(CRITICAL)
}

func fetchHealthz(endpoint, tlsClientCert, tlsClientKey, tlsClientRootCaFile string) (map[string]interface{}, error) {
	client := &http.Client{}
	if tlsClientCert != "" && tlsClientKey != "" && tlsClientRootCaFile != "" {
		// Load client cert
		cert, err := tls.LoadX509KeyPair(tlsClientCert, tlsClientKey)
		if err != nil {
			return nil, err
		}

		// Load CA cert
		caCert, err := ioutil.ReadFile(tlsClientRootCaFile)
		if err != nil {
			return nil, err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		// Setup HTTPS client
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caCertPool,
		}
		tlsConfig.BuildNameToCertificate()
		client.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	}

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	m := make(map[string]interface{})
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, err
	}

	return m, nil
}
