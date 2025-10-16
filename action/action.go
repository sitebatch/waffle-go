package action

import (
	"fmt"
)

type BlockError struct {
	RuleID    string
	Inspector string
}

func (e *BlockError) Error() string {
	return fmt.Sprintf("blocked by rule %s with inspector %s", e.RuleID, e.Inspector)
}
