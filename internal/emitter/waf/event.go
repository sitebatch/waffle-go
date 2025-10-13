package waf

import (
	"time"

	"github.com/sitebatch/waffle-go/internal/emitter/waf/wafcontext"
	"github.com/sitebatch/waffle-go/internal/operation"
	"github.com/sitebatch/waffle-go/internal/rule"
)

type ReadOnlyDetectionEvents interface {
	Events() []DetectionEvent
	Operation() operation.Operation
}

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
	Context *DetectionContext

	Rule      rule.Rule
	Inspector string
	Message   string
	Payload   string

	// Time is the time when the event was detected.
	Time time.Time
}

func NewDetectionEvent(wafOpCtx *wafcontext.WafOperationContext, rule rule.Rule, inspector, message, payload string) DetectionEvent {
	context := NewDetectionContext(wafOpCtx)

	return DetectionEvent{
		Context:   context,
		Rule:      rule,
		Inspector: inspector,
		Message:   message,
		Payload:   payload,
		Time:      time.Now(),
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
