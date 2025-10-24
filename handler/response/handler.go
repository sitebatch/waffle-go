package response

import (
	_ "embed"
	"net/http"
	"strings"
	"sync/atomic"
)

var (
	//go:embed templates/blocked.html
	defaultBlockResponseTemplateHTMLBytes []byte

	defaultBlockResponseTemplateJSONBytes = []byte(`{"error": "access denied. Sorry, you cannnot access this resource. Please contact the customer support."}`)

	blockResponseTemplateHTML = blockResponseTemplateHTMLValue()
	blockResponseTemplateJSON = blockResponseTemplateJSONValue()
)

func SetBlockResponseTemplateHTML(html []byte) {
	blockResponseTemplateHTML.Store(html)
}

func SetBlockResponseTemplateJSON(json []byte) {
	blockResponseTemplateJSON.Store(json)
}

func GetBlockResponseTemplateHTML() []byte {
	return blockResponseTemplateHTML.Load().([]byte)
}

func GetBlockResponseTemplateJSON() []byte {
	return blockResponseTemplateJSON.Load().([]byte)
}

func BlockResponseHandler(contentType string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)

		accept := r.Header.Get("Accept")

		if strings.Contains(contentType, "application/json") || strings.Contains(accept, "application/json") {
			w.Header().Add("Content-Type", "application/json")
			_, _ = w.Write(GetBlockResponseTemplateJSON())
			return
		}

		w.Header().Add("Content-Type", "text/html")
		_, _ = w.Write(GetBlockResponseTemplateHTML())
	})
}

func blockResponseTemplateHTMLValue() *atomic.Value {
	v := &atomic.Value{}
	v.Store(defaultBlockResponseTemplateHTMLBytes)

	return v
}

func blockResponseTemplateJSONValue() *atomic.Value {
	v := &atomic.Value{}
	v.Store(defaultBlockResponseTemplateJSONBytes)

	return v
}
