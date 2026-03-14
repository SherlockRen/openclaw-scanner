package vulnscan

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"openclaw-scan/internal/models"

	"github.com/spaolacci/murmur3"
)

const defaultOpenClawFaviconMMH3 int32 = -1172715710

var openClawFaviconPaths = []string{"/favicon.svg", "/favicon.ico"}

func DetectOpenClawFingerprint(target string, openPorts []int) []models.Finding {
	findings := make([]models.Finding, 0)
	for _, port := range openPorts {
		if port < 1 || port > 65535 {
			continue
		}
		hits := make([]string, 0)
		seenHit := map[string]struct{}{}
		accessURL := preferredAccessURL(target, port)
		for _, base := range []string{fmt.Sprintf("http://%s:%d", target, port), fmt.Sprintf("https://%s:%d", target, port)} {
			if strings.HasPrefix(base, "https://") {
				accessURL = base
			}
			if matched, detail := detectTitleBodyFingerprint(base); matched {
				addHit(&hits, seenHit, "OPENCLAW-HTML", detail)
			}
			if matched, detail := detectHeaderFingerprint(base); matched {
				addHit(&hits, seenHit, "OPENCLAW-HEADER", detail)
			}
			if matched, detail := detectHealthFingerprint(base); matched {
				addHit(&hits, seenHit, "OPENCLAW-HEALTH", detail)
			}
			if matched, detail := detectFaviconFingerprint(base, defaultOpenClawFaviconMMH3); matched {
				addHit(&hits, seenHit, "OPENCLAW-FAVICON", detail)
			}
		}
		if len(hits) > 0 {
			findings = append(findings, buildOpenClawFinding(target, port, hits, accessURL))
		}
	}
	return findings
}

func addHit(hits *[]string, seen map[string]struct{}, ruleID string, detail string) {
	key := ruleID + "|" + detail
	if _, ok := seen[key]; ok {
		return
	}
	seen[key] = struct{}{}
	*hits = append(*hits, fmt.Sprintf("%s: %s", ruleID, detail))
}

func preferredAccessURL(target string, port int) string {
	if port == 443 || port == 8443 {
		return fmt.Sprintf("https://%s:%d", target, port)
	}
	return fmt.Sprintf("http://%s:%d", target, port)
}

func detectTitleBodyFingerprint(base string) (bool, string) {
	status, _, body, err := probe(base, 3*time.Second)
	if err != nil || status <= 0 {
		return false, ""
	}
	lower := strings.ToLower(body)
	titleRe := regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	m := titleRe.FindStringSubmatch(lower)
	if len(m) > 1 {
		title := strings.TrimSpace(m[1])
		if strings.Contains(title, "Openclaw") || strings.Contains(title, "Moltbot") || strings.Contains(title, "Clawdbot") {
			return true, fmt.Sprintf("title matched: %s", title)
		}
	}
	if strings.Contains(lower, "<moltbot-app></moltbot-app>") || strings.Contains(lower, "<openclaw-app></openclaw-app>") || strings.Contains(lower, "<clawdbot-app></clawdbot-app>") {
		return true, "body app tag matched"
	}
	return false, ""
}

func detectHeaderFingerprint(base string) (bool, string) {
	status, headers, _, err := probe(base, 3*time.Second)
	if err != nil || status <= 0 {
		return false, ""
	}
	server := strings.ToLower(headers.Get("Server"))
	powered := strings.ToLower(headers.Get("X-Powered-By"))
	if strings.Contains(server, "openclaw") {
		return true, "Server header contains OpenClaw"
	}
	if strings.Contains(powered, "openclaw") {
		return true, "X-Powered-By header contains OpenClaw"
	}
	return false, ""
}

func detectHealthFingerprint(base string) (bool, string) {
	status, _, body, err := probe(base+"/api/v1/health", 3*time.Second)
	if err != nil || status < 200 || status >= 300 {
		return false, ""
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		return false, ""
	}
	if service, ok := payload["service"].(string); ok && strings.EqualFold(service, "openclaw") {
		return true, "health api json contains service=openclaw"
	}
	return false, ""
}

func detectFaviconFingerprint(base string, expected int32) (bool, string) {
	if p, ok := extractIconPathFromHTML(base); ok {
		status, _, body, err := probe(base+p, 3*time.Second)
		if err == nil && status >= 200 && status < 300 {
			h := faviconMMH3([]byte(body))
			if h == expected {
				return true, fmt.Sprintf("favicon html path=%s mmh3 matched %d", p, expected)
			}
		}
	}
	for _, p := range openClawFaviconPaths {
		status, _, body, err := probe(base+p, 3*time.Second)
		if err != nil || status < 200 || status >= 300 {
			continue
		}
		h := faviconMMH3([]byte(body))
		if h == expected {
			return true, fmt.Sprintf("favicon path=%s mmh3 matched %d", p, expected)
		}
	}
	return false, ""
}

func extractIconPathFromHTML(base string) (string, bool) {
	status, _, body, err := probe(base, 3*time.Second)
	if err != nil || status < 200 || status >= 300 {
		return "", false
	}
	lower := strings.ToLower(body)
	re := regexp.MustCompile(`(?i)<link[^>]*rel=["'][^"']*icon[^"']*["'][^>]*href=["']([^"']+)["'][^>]*>`)
	m := re.FindStringSubmatch(lower)
	if len(m) < 2 {
		return "", false
	}
	raw := strings.TrimSpace(m[1])
	if raw == "" {
		return "", false
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		u, err := url.Parse(raw)
		if err != nil || u.Path == "" {
			return "", false
		}
		if u.RawQuery != "" {
			return u.Path + "?" + u.RawQuery, true
		}
		return u.Path, true
	}
	if strings.HasPrefix(raw, "./") {
		return "/" + strings.TrimPrefix(raw, "./"), true
	}
	if strings.HasPrefix(raw, "/") {
		return raw, true
	}
	return "/" + raw, true
}

func faviconMMH3(raw []byte) int32 {
	encoded := base64.StdEncoding.EncodeToString(raw)
	var b strings.Builder
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		b.WriteString(encoded[i:end])
		b.WriteByte('\n')
	}
	return int32(murmur3.Sum32([]byte(b.String())))
}

func probe(url string, timeout time.Duration) (int, http.Header, string, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{Timeout: timeout, Transport: transport}
	resp, err := client.Get(url)
	if err != nil {
		return 0, nil, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return 0, nil, "", err
	}
	return resp.StatusCode, resp.Header.Clone(), string(b), nil
}

func buildOpenClawFinding(target string, port int, hits []string, accessURL string) models.Finding {
	confidence := "medium"
	if len(hits) > 1 {
		confidence = "high"
	}
	evidence := strings.Join(hits, " | ")
	return models.Finding{FindingID: fmt.Sprintf("f-fp-%s-%d", target, port), FindingType: "sensitive-info", Severity: "medium", RuleID: "OPENCLAW-FINGERPRINT", Target: target, Port: port, AccessURL: accessURL, EvidencePattern: evidence, EvidenceMasked: evidence, Confidence: confidence, RequiresManualReview: false, FalsePositiveState: "none", Recommendation: "confirm OpenClaw asset ownership and hardening baseline"}
}
