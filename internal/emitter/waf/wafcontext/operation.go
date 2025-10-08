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

func (c *WafOperationContext) GetMeta() map[string]string {
	if c.Meta == nil {
		return make(map[string]string)
	}

	return c.Meta
}

func (c *WafOperationContext) GetHttpRequest() *HttpRequest {
	if c.HttpRequest == nil {
		return &HttpRequest{}
	}

	return c.HttpRequest
}
