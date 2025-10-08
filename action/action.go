package action

import (
	"fmt"

	"github.com/sitebatch/waffle-go/internal/emitter/waf/wafcontext"
)

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
	Payload   string
	Context   *DetectionContext
}

type BlockError struct {
	RuleID    string
	Inspector string
}

func (e *BlockError) Error() string {
	return fmt.Sprintf("blocked by rule %s with inspector %s", e.RuleID, e.Inspector)
}

func NewDeetectionEvent(ruleID, inspector, message, payload string, context *DetectionContext) DetectionEvent {
	return DetectionEvent{
		RuleID:    ruleID,
		Inspector: inspector,
		Message:   message,
		Context:   context,
	}
}

func NewDetectionContext(wafOpCtx *wafcontext.WafOperationContext) *DetectionContext {
	if wafOpCtx == nil {
		return &DetectionContext{}
	}

	req := wafOpCtx.GetHttpRequest()

	return &DetectionContext{
		Meta: wafOpCtx.GetMeta(),
		HttpRequest: &HttpRequest{
			URL:      req.URL,
			Headers:  req.Headers,
			Body:     req.Body,
			ClientIP: req.ClientIP,
		},
	}
}
