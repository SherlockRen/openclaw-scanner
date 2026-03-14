package vulnscan

import (
	"fmt"
	"strings"

	"openclaw-scan/internal/models"
)

type Fingerprint struct {
	Target  string
	Port    int
	Service string
	Product string
	Version string
}

func BuildFingerprints(target string, openPorts []int, services map[int]string, products map[int]string, versions map[int]string) []Fingerprint {
	out := make([]Fingerprint, 0, len(openPorts))
	for _, p := range openPorts {
		out = append(out, Fingerprint{Target: target, Port: p, Service: strings.ToLower(strings.TrimSpace(services[p])), Product: strings.ToLower(strings.TrimSpace(products[p])), Version: strings.TrimSpace(versions[p])})
	}
	return out
}

func fingerprintString(fp Fingerprint) string {
	return fmt.Sprintf("%s:%d %s %s %s", fp.Target, fp.Port, fp.Service, fp.Product, fp.Version)
}

func detectVersionVulns(fps []Fingerprint, rules []VersionRule) []models.Finding {
	findings := make([]models.Finding, 0)
	for _, fp := range fps {
		for _, r := range rules {
			if r.ProductContains == "" || fp.Product == "" {
				continue
			}
			if !strings.Contains(fp.Product, r.ProductContains) {
				continue
			}
			if !versionLessThan(fp.Version, r.BaselineVersion) {
				continue
			}
			findings = append(findings, models.Finding{
				FindingID:            fmt.Sprintf("f-ver-%s-%d-%s", fp.Target, fp.Port, r.RuleID),
				FindingType:          "vulnerability",
				Severity:             r.Severity,
				RuleID:               r.RuleID,
				Target:               fp.Target,
				Port:                 fp.Port,
				EvidencePattern:      fmt.Sprintf("version<%s", r.BaselineVersion),
				EvidenceMasked:       fingerprintString(fp),
				Confidence:           "medium",
				RequiresManualReview: false,
				FalsePositiveState:   "none",
				Recommendation:       r.Recommendation,
			})
		}
	}
	return findings
}
