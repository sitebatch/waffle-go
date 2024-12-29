package parser

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/jeremywohl/flatten"
)

type jsonParser struct{}

func (jsonParser) Parse(req *http.Request) (map[string][]string, error) {
	ctx := req.Context()
	copy := req.Clone(ctx)
	b, err := io.ReadAll(copy.Body)
	if err != nil {
		return nil, err
	}
	defer copy.Body.Close()

	req.Body = io.NopCloser(bytes.NewBuffer(b))

	var j map[string]interface{}

	if err := json.Unmarshal(b, &j); err != nil {
		return nil, err
	}

	flat, err := flatten.Flatten(j, "", flatten.DotStyle)
	if err != nil {
		return nil, err
	}

	result := make(map[string][]string)
	for k, v := range flat {
		if s, ok := v.(string); ok {
			result[k] = []string{s}
		}
	}

	return result, nil
}
