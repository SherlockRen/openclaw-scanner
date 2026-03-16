package discovery

import "openclaw-scan/internal/vulnscan"
import "openclaw-scan/internal/models"
import "time"

func DetectOpenClawFingerprint(target string, openPorts []int, timeout time.Duration, onRequest func(url string)) []models.Finding {
	return vulnscan.DetectOpenClawFingerprint(target, openPorts, timeout, onRequest)
}
