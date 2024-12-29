package validator

import (
	"fmt"

	"github.com/sitebatch/waffle-go/internal/inspector"
)

func ValidateInspector(inspectorName, target string) error {
	inspectors := inspector.NewInspector()
	i, ok := inspectors[inspectorName]
	if !ok {
		return fmt.Errorf("inspector %s not found", inspectorName)
	}

	if !i.IsSupportTarget(inspector.InspectTarget(target)) {
		return fmt.Errorf("inspector %s does not support target %s", inspectorName, target)
	}

	return nil
}
