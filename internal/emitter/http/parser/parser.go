package parser

import (
	"net/http"
)

type parser interface {
	Parse(r *http.Request) (map[string][]string, error)
}

func ParseHTTPRequestBody(r *http.Request) (map[string][]string, error) {
	p := newParser(r.Method, r.Header.Get("Content-Type"))
	return p.Parse(r)
}

func newParser(method, contentType string) parser {
	if method == http.MethodGet {
		return &formParser{}
	}

	switch contentType {
	case "application/json":
		return &jsonParser{}
	case "multipart/form-data":
		return &multipartParser{}
	default:
		return &formParser{}
	}
}
