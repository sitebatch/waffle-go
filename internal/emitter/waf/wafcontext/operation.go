package wafcontext

type HttpRequest struct {
	URL      string
	Headers  map[string][]string
	Body     map[string][]string
	ClientIP string
}

type WafOperationContext struct {
	Meta        map[string]string
	HttpRequest *HttpRequest
}
