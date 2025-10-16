package parser

import (
	"errors"
	"net/http"
)

const defaultMemory = 32 << 20

type formParser struct{}
type multipartParser struct{}

func (formParser) Parse(req *http.Request) (map[string][]string, error) {
	if err := req.ParseForm(); err != nil {
		return nil, err
	}

	if err := req.ParseMultipartForm(defaultMemory); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		return nil, err
	}

	return req.PostForm, nil
}

func (multipartParser) Parse(req *http.Request) (map[string][]string, error) {
	if err := req.ParseMultipartForm(defaultMemory); err != nil {
		return nil, err
	}

	return req.MultipartForm.Value, nil
}
