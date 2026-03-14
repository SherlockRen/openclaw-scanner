package discovery

import "openclaw-scan/internal/vulnscan"
import "openclaw-scan/internal/models"

func DetectOpenClawFingerprint(target string, openPorts []int) []models.Finding {
	return vulnscan.DetectOpenClawFingerprint(target, openPorts)
}
