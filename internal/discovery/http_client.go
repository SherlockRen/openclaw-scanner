package discovery

import (
	"crypto/tls"
	"net/http"
	"time"
)

func netHTTPClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return &http.Client{Timeout: timeout, Transport: transport}
}
