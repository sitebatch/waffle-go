package libinjection

import (
	"fmt"

	"github.com/sitebatch/waffle-go/lib"
)

func IsSQLiPayload(value string) error {
	var fingerprint string
	isSQLi := lib.LibinjectionSQLiFunc(value, len(value), fingerprint)
	if isSQLi == 1 {
		return fmt.Errorf("SQLi detected")
	}

	return nil
}
