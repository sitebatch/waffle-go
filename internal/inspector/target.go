package inspector

import (
	"net/http"
	"net/url"
)

type InspectTarget string

const (
	InspectTargetHttpRequestURL    InspectTarget = "http.request.url"
	InspectTargetHttpRequestPath   InspectTarget = "http.request.path"
	InspectTargetHttpRequestHeader InspectTarget = "http.request.header"
	InspectTargetHttpRequestQuery  InspectTarget = "http.request.query"
	InspectTargetHttpRequestBody   InspectTarget = "http.request.body"
	InspectTargetClientIP          InspectTarget = "client.ip"

	InspectTargetHttpClientRequestURL InspectTarget = "http.client.request.url"

	InspectTargetSQLQuery   InspectTarget = "sql.query"
	InspectTargetOSFileOpen InspectTarget = "os.file.open"
)

func (t InspectTarget) String() string {
	return string(t)
}

func (t InspectTarget) IsSupportKeyValueFiltering() bool {
	switch t {
	case InspectTargetHttpRequestHeader, InspectTargetHttpRequestQuery, InspectTargetHttpRequestBody:
		return true
	default:
		return false
	}
}

type InspectData struct {
	Target map[InspectTarget]InspectTargetValue
}

type InspectDataBuilder struct {
	InspectData
}

func NewInspectDataBuilder() *InspectDataBuilder {
	return &InspectDataBuilder{
		InspectData: InspectData{
			Target: make(map[InspectTarget]InspectTargetValue),
		},
	}
}

func (b *InspectDataBuilder) WithHTTPRequestURL(url string) *InspectDataBuilder {
	b.Target[InspectTargetHttpRequestURL] = NewInspectTargetValueString(url)
	return b
}

func (b *InspectDataBuilder) WithHTTPRequestHeader(header http.Header) *InspectDataBuilder {
	b.Target[InspectTargetHttpRequestHeader] = NewInspectTargetValueKeyValues(header)
	return b
}

func (b *InspectDataBuilder) WithHTTPRequestQuery(query url.Values) *InspectDataBuilder {
	b.Target[InspectTargetHttpRequestQuery] = NewInspectTargetValueKeyValues(query)
	return b
}

func (b *InspectDataBuilder) WithHTTPRequestBody(body map[string][]string) *InspectDataBuilder {
	b.Target[InspectTargetHttpRequestBody] = NewInspectTargetValueKeyValues(body)
	return b
}

func (b *InspectDataBuilder) WithClientIP(clientIP string) *InspectDataBuilder {
	b.Target[InspectTargetClientIP] = NewInspectTargetValueString(clientIP)
	return b
}

func (b *InspectDataBuilder) WithHTTPClientRequestURL(url string) *InspectDataBuilder {
	b.Target[InspectTargetHttpClientRequestURL] = NewInspectTargetValueString(url)
	return b
}

func (b *InspectDataBuilder) WithSQLQuery(query string) *InspectDataBuilder {
	b.Target[InspectTargetSQLQuery] = NewInspectTargetValueString(query)
	return b
}

func (b *InspectDataBuilder) WithFileOpenPath(path string) *InspectDataBuilder {
	b.Target[InspectTargetOSFileOpen] = NewInspectTargetValueString(path)
	return b
}

func (b *InspectDataBuilder) Build() *InspectData {
	return &b.InspectData
}

func (d *InspectData) HasTarget(target InspectTarget) bool {
	_, exists := d.Target[target]
	return exists
}
