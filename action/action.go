package action

import "errors"

var _ error = (*BlockError)(nil)

type BlockError struct {
	RuleID    string
	Inspector string
}

func (e *BlockError) Error() string {
	return "request blocked by WAF"
}

func IsBlockError(err error) bool {
	var blockErr *BlockError
	return errors.As(err, &blockErr)
}
