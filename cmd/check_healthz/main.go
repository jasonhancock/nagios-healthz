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
	"sort"
	"strings"

	"github.com/jasonhancock/healthz"
)

// Nagios exit code statuses
const CRITICAL int = 2
const OK int = 0

func main() {

	var (
		endpoint = flag.String("endpoint", "", "URL of healthz endpoint to check")

		tlsClientCert       = flag.String("tls-client-cert", "", "path to certificate file used to connect to data_api and control_api")
		tlsClientKey        = flag.String("tls-client-key", "", "path to private key file used to connect to data_api and control_api")
		tlsClientRootCaFile = flag.String("tls-client-root-ca-file", "", "path to private certificate authority certificate used to connect to data_api and control_api")
	)
	flag.Parse()

	if *endpoint == "" {
		log.Fatal("Set the -endpoint flag")
	}

	var checksOk []string
	var checksError []string

	cr, err := fetchHealthz(*endpoint, *tlsClientCert, *tlsClientKey, *tlsClientRootCaFile)
	if err != nil || cr == nil {
		fmt.Println("ERROR: Unable to fetch healthz endpoint - ", err)
		os.Exit(CRITICAL)
	}

	var status int = OK
	keys := sortedMapKeys(cr)
	for _, name := range keys {
		if cr[name].ErrorMessage != "" {
			status = CRITICAL
			checksError = append(checksError, name+": "+cr[name].ErrorMessage)
		} else {
			checksOk = append(checksOk, name)
		}
	}

	// You get one line of output + the exit code to communicate with Nagios. Build an
	// informative status message
	var statusMessage string
	if len(checksError) > 0 {
		statusMessage += "ERROR: " + strings.Join(checksError, ", ") + " "
	}

	if len(checksOk) > 0 {
		statusMessage += "OK: " + strings.Join(checksOk, ", ")
	} else {
		statusMessage += "OK: none"
	}

	fmt.Println(statusMessage)
	os.Exit(status)
}

func sortedMapKeys(m map[string]healthz.Response) []string {
	keys := make([]string, len(m))

	i := 0
	for k := range m {
		keys[i] = k
		i++
	}

	sort.Strings(keys)
	return keys
}

func fetchHealthz(endpoint, tlsClientCert, tlsClientKey, tlsClientRootCaFile string) (map[string]healthz.Response, error) {
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

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	m := make(map[string]healthz.Response)
	err = json.Unmarshal(body, &m)
	if err != nil {
		return nil, err
	}

	return m, nil
}
