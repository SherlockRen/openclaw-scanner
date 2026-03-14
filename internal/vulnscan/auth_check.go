package vulnscan

import (
	"fmt"

	"openclaw-scan/internal/models"
)

func ValidateAuthorization(a models.Authorization) error {
	if a.Requester == "" || a.Scope == "" || a.TimeWindow == "" || a.Source == "" {
		return fmt.Errorf("authorization requires requester/scope/time-window/source")
	}
	return nil
}
