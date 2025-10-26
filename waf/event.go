package waf

import (
	"errors"
	"time"

	"github.com/sitebatch/waffle-go/internal/inspector"
	"github.com/sitebatch/waffle-go/internal/operation"
	"github.com/sitebatch/waffle-go/internal/rule"
	"github.com/sitebatch/waffle-go/waf/wafcontext"
)

var _ error = (*SecurityBlockingError)(nil)

// SecurityBlockingError indicates that processing has been blocked by the WAF during function calls.
// When a function call is blocked by the WAF, it is the user's responsibility to forcibly terminate processing at that endpoint.
// For example, if SQL query execution is blocked by the WAF during endpoint processing, a SecurityBlockingError type error is returned.
// In this case, the SQL query execution should be aborted and the processing of that endpoint should be terminated.
type SecurityBlockingError struct{}

func (e *SecurityBlockingError) Error() string {
	return "request blocked by WAF"
}

func IsSecurityBlockingError(err error) bool {
	var blockErr *SecurityBlockingError
	return errors.As(err, &blockErr)
}

type ReadOnlyDetectionEvents interface {
	Events() []DetectionEvent
	Operation() operation.Operation
}

type HttpRequest struct {
	URL      string
	Headers  map[string][]string
	RawBody  []byte
	Body     map[string][]string
	ClientIP string
}

type DetectionContext struct {
	Meta        map[string]string
	HttpRequest *HttpRequest
}

type DetectionEvent struct {
	Context *DetectionContext

	Rule      rule.Rule
	Inspector string
	InspectAt inspector.InspectTarget
	Message   string
	Payload   string

	// DetectedAt is the time when the event was detected.
	DetectedAt time.Time
}

func NewDetectionEvent(wafOpCtx *wafcontext.WafOperationContext, result EvalResult) DetectionEvent {
	context := NewDetectionContext(wafOpCtx)

	return DetectionEvent{
		Context:    context,
		Rule:       result.Rule,
		Inspector:  result.InspectBy,
		InspectAt:  result.InspectResult.Target,
		Message:    result.InspectResult.Message,
		Payload:    result.InspectResult.Payload,
		DetectedAt: time.Now(),
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
			RawBody:  req.RawBody,
			Body:     req.Body,
			ClientIP: req.ClientIP,
		},
	}
}
