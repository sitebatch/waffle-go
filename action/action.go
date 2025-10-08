package action

import "fmt"

type HttpRequest struct {
	URL      string
	Headers  map[string][]string
	Body     map[string][]string
	ClientIP string
}

type DetectionContext struct {
	Meta        map[string]string
	HttpRequest *HttpRequest
}

type DetectionEvent struct {
	RuleID    string
	Inspector string
	Message   string
	Context   DetectionContext
}

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
