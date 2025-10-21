package wafcontext

type HttpRequest struct {
	URL      string
	Headers  map[string][]string
	RawBody  []byte
	Body     map[string][]string
	ClientIP string
}

// WafOperationContext holds context information for a WAF operation.
type WafOperationContext struct {
	meta        map[string]string
	httpRequest *HttpRequest
}

func WithMeta(meta map[string]string) WafOperationContextOption {
	return func(c *WafOperationContext) {
		c.meta = meta
	}
}

func WithHttpRequstContext(req HttpRequest) WafOperationContextOption {
	return func(c *WafOperationContext) {
		c.httpRequest = &req
	}
}

type WafOperationContextOption func(*WafOperationContext)

func NewWafOperationContext(opts ...WafOperationContextOption) *WafOperationContext {
	c := &WafOperationContext{
		meta: make(map[string]string),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// WithWafOperationContext applies the given options to the WafOperationContext and returns the modified context.
func (c *WafOperationContext) WithWafOperationContext(opts ...WafOperationContextOption) *WafOperationContext {
	for _, opt := range opts {
		opt(c)
	}

	return c
}

func (c *WafOperationContext) GetMeta() map[string]string {
	if c.meta == nil {
		return make(map[string]string)
	}

	return c.meta
}

func (c *WafOperationContext) SetMeta(key, value string) {
	if c.meta == nil {
		c.meta = make(map[string]string)
	}
	c.meta[key] = value
}

func (c *WafOperationContext) GetHttpRequest() *HttpRequest {
	if c.httpRequest == nil {
		return &HttpRequest{}
	}

	return c.httpRequest
}
