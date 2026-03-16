package vulnscan

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"openclaw-scan/internal/models"
)

func DetectPathLeaks(target string, openPorts []int, timeout time.Duration, onRequest func(url string)) []models.Finding {
	findings := make([]models.Finding, 0)
	paths := []string{"/.env", "/.git/config", "/phpinfo.php", "/backup.zip", "/config.php.bak"}
	for _, port := range openPorts {
		if port != 80 && port != 443 && port != 8080 && port != 8443 && port != 18789 && port != 19001 {
			continue
		}
		scheme := "http"
		if port == 443 || port == 8443 {
			scheme = "https"
		}
		for _, p := range paths {
			url := fmt.Sprintf("%s://%s:%d%s", scheme, target, port, p)
			status, contentType, body, err := probeHTTP(url, timeout, onRequest)
			if err != nil {
				continue
			}
			if status >= 200 && status < 300 && looksSensitive(body, contentType, p) {
				masked := "http resource exposed with sensitive-like content"
				if len(body) > 0 {
					snippet := body
					if len(snippet) > 120 {
						snippet = snippet[:120]
					}
					masked = fmt.Sprintf("http resource exposed, sample=%q", snippet)
				}
				findings = append(findings, models.Finding{
					FindingID:            fmt.Sprintf("f-poc-%s-%d-%s", target, port, strings.TrimPrefix(p, "/")),
					FindingType:          "sensitive-info",
					Severity:             "high",
					RuleID:               "POC-LEAK-HTTP-EXPOSED",
					Target:               target,
					Port:                 port,
					AccessURL:            url,
					EvidencePattern:      p,
					EvidenceMasked:       masked,
					Confidence:           "high",
					RequiresManualReview: false,
					FalsePositiveState:   "none",
					Recommendation:       "restrict access and remove sensitive files from web root",
				})
			}
		}
	}
	return findings
}

func probeHTTP(url string, timeout time.Duration, onRequest func(url string)) (int, string, string, error) {
	if onRequest != nil {
		onRequest(url)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{Timeout: timeout, Transport: transport}
	resp, err := client.Get(url)
	if err != nil {
		return 0, "", "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if err != nil {
		return 0, "", "", err
	}
	return resp.StatusCode, strings.ToLower(resp.Header.Get("Content-Type")), strings.ToLower(string(b)), nil
}

func looksSensitive(body, contentType, path string) bool {
	if path == "/.env" && (strings.Contains(body, "db_password") || strings.Contains(body, "secret") || strings.Contains(body, "token")) {
		return true
	}
	if path == "/.git/config" && strings.Contains(body, "[core]") {
		return true
	}
	if path == "/phpinfo.php" && strings.Contains(body, "php version") {
		return true
	}
	if path == "/backup.zip" {
		if strings.HasPrefix(body, "pk\x03\x04") {
			return true
		}
		if strings.Contains(contentType, "application/zip") || strings.Contains(contentType, "application/octet-stream") {
			return true
		}
		return false
	}
	if path == "/config.php.bak" {
		if strings.Contains(contentType, "text/html") && strings.Contains(body, "<html") {
			return false
		}
		if strings.Contains(body, "<?php") || strings.Contains(body, "$db") || strings.Contains(body, "password") {
			return true
		}
		if strings.Contains(contentType, "text/plain") && len(strings.TrimSpace(body)) > 0 {
			return true
		}
		return false
	}
	if strings.Contains(contentType, "text/html") && strings.Contains(body, "<html") {
		return false
	}
	if strings.Contains(body, "openclaw-app") || strings.Contains(body, "moltbot-app") || strings.Contains(body, "clawdbot-app") {
		return false
	}
	if strings.Contains(body, "<!doctype html") {
		return false
	}
	if strings.Contains(body, "password") || strings.Contains(body, "token") || strings.Contains(body, "secret") {
		return true
	}
	return false
}
