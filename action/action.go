package action

import "fmt"

type DetectionError struct {
	Reason string
}

type BlockError struct {
	RuleID    string
	Inspector string
}

func (e *DetectionError) Error() string {
	return e.Reason
}

func (e *BlockError) Error() string {
	return fmt.Sprintf("blocked by rule %s with inspector %s", e.RuleID, e.Inspector)
}
