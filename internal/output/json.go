package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"openclaw-scan/internal/models"
)

func WriteJSON(report models.Report, outputFile string) error {
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if outputFile == "" {
		fmt.Println(string(b))
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(outputFile), 0o755); err != nil && filepath.Dir(outputFile) != "." {
		return err
	}
	if err := os.WriteFile(outputFile, append(b, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("report written: %s\n", outputFile)
	return nil
}
