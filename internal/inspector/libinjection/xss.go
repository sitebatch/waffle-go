package libinjection

import (
	"fmt"

	"github.com/sitebatch/waffle-go/lib"
)

func IsXSSPayload(value string) error {
	if isXSS := lib.LibinjectionXSSFunc(value, len(value)); isXSS == 1 {
		return fmt.Errorf("XSS detected")
	}

	return nil
}
