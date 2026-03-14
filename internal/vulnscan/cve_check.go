package vulnscan

import (
	"openclaw-scan/internal/models"
)

type VersionRule struct {
	RuleID          string
	ProductContains string
	BaselineVersion string
	Severity        string
	Recommendation  string
}

func defaultVersionRules() []VersionRule {
	return []VersionRule{
		{RuleID: "VULN-VERSION-OPENSSH", ProductContains: "openssh", BaselineVersion: "8.4", Severity: "medium", Recommendation: "upgrade openssh to >= 8.4"},
		{RuleID: "VULN-VERSION-NGINX", ProductContains: "nginx", BaselineVersion: "1.20.0", Severity: "medium", Recommendation: "upgrade nginx to >= 1.20.0"},
		{RuleID: "VULN-VERSION-APACHE", ProductContains: "apache", BaselineVersion: "2.4.58", Severity: "medium", Recommendation: "upgrade apache to >= 2.4.58"},
	}
}

func DetectVersionVulns(h models.HostScan) []models.Finding {
	fps := BuildFingerprints(h.Target, h.OpenPorts, h.Services, h.Products, h.Versions)
	return detectVersionVulns(fps, defaultVersionRules())
}
