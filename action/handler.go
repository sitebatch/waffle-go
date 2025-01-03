package action

import (
	_ "embed"
	"net/http"
	"strings"
)

//go:embed templates/blocked.html
var blockResponseTemplateHTML []byte

var blockResponseTemplateJSON = []byte(`{"error": "access denied. Sorry, you cannnot access this resource. Please contact the customer support."}`)

func RegisterBlockResponseTemplateHTML(html []byte) {
	blockResponseTemplateHTML = html
}

func RegisterBlockResponseTemplateJSON(json []byte) {
	blockResponseTemplateJSON = json
}

func BlockResponseHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)

		accept := r.Header.Get("Accept")
		if strings.Contains(accept, "application/json") {
			w.Header().Add("Content-Type", "application/json")
			w.Write(blockResponseTemplateJSON)
			return
		}

		// default to html
		w.Header().Add("Content-Type", "text/html")
		w.Write(blockResponseTemplateHTML)
	})
}
