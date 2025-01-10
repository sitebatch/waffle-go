package inspector

import (
	"net/http"
	"net/url"

	"github.com/sitebatch/waffle-go/internal/inspector/types"
)

type InspectTarget string

const (
	InspectTargetHttpRequestURL    InspectTarget = "http.request.url"
	InspectTargetHttpRequestPath   InspectTarget = "http.request.path"
	InspectTargetHttpRequestHeader InspectTarget = "http.request.header"
	InspectTargetHttpRequestQuery  InspectTarget = "http.request.query"
	InspectTargetHttpRequestBody   InspectTarget = "http.request.body"
	InspectTargetClientIP          InspectTarget = "client.ip"

	InspectTargetGraphQLRequestRawQuery      InspectTarget = "graphql.request.raw_query"
	InspectTargetGraphQLRequestOperationName InspectTarget = "graphql.request.operation_name"
	InspectTargetGraphQLRequestVariables     InspectTarget = "graphql.request.variables"

	InspectTargetHttpClientRequestURL InspectTarget = "http.client.request.url"

	InspectTargetSQLQuery   InspectTarget = "sql.query"
	InspectTargetOSFileOpen InspectTarget = "os.file.open"

	InspectTargetAccountTakeover InspectTarget = "application.user.login.account_takeover"
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
	Target map[InspectTarget]types.InspectTargetValue
}

type InspectDataBuilder struct {
	InspectData
}

func NewInspectDataBuilder() *InspectDataBuilder {
	return &InspectDataBuilder{
		InspectData: InspectData{
			Target: make(map[InspectTarget]types.InspectTargetValue),
		},
	}
}

func (b *InspectDataBuilder) WithHTTPRequestURL(url string) *InspectDataBuilder {
	b.Target[InspectTargetHttpRequestURL] = types.NewStringValue(url)
	return b
}

func (b *InspectDataBuilder) WithHTTPRequestHeader(header http.Header) *InspectDataBuilder {
	b.Target[InspectTargetHttpRequestHeader] = types.NewKeyValues(header)
	return b
}

func (b *InspectDataBuilder) WithHTTPRequestQuery(query url.Values) *InspectDataBuilder {
	b.Target[InspectTargetHttpRequestQuery] = types.NewKeyValues(query)
	return b
}

func (b *InspectDataBuilder) WithHTTPRequestBody(body map[string][]string) *InspectDataBuilder {
	b.Target[InspectTargetHttpRequestBody] = types.NewKeyValues(body)
	return b
}

func (b *InspectDataBuilder) WithClientIP(clientIP string) *InspectDataBuilder {
	b.Target[InspectTargetClientIP] = types.NewStringValue(clientIP)
	return b
}

func (b *InspectDataBuilder) WithHTTPClientRequestURL(url string) *InspectDataBuilder {
	b.Target[InspectTargetHttpClientRequestURL] = types.NewStringValue(url)
	return b
}

func (b *InspectDataBuilder) WithGraphQLRequestRawQuery(query string) *InspectDataBuilder {
	b.Target[InspectTargetGraphQLRequestRawQuery] = types.NewStringValue(query)
	return b
}

func (b *InspectDataBuilder) WithGraphQLRequestOperationName(operationName string) *InspectDataBuilder {
	b.Target[InspectTargetGraphQLRequestOperationName] = types.NewStringValue(operationName)
	return b
}

func (b *InspectDataBuilder) WithGraphQLRequestVariables(variables map[string][]string) *InspectDataBuilder {
	b.Target[InspectTargetGraphQLRequestVariables] = types.NewKeyValues(variables)
	return b
}

func (b *InspectDataBuilder) WithSQLQuery(query string) *InspectDataBuilder {
	b.Target[InspectTargetSQLQuery] = types.NewStringValue(query)
	return b
}

func (b *InspectDataBuilder) WithFileOpenPath(path string) *InspectDataBuilder {
	b.Target[InspectTargetOSFileOpen] = types.NewStringValue(path)
	return b
}

func (b *InspectDataBuilder) WithAccountTakeover(clientIP, userID string) *InspectDataBuilder {
	b.Target[InspectTargetAccountTakeover] = types.NewKeyValues(map[string][]string{
		"client_ip": {clientIP},
		"user_id":   {userID},
	})
	return b
}

func (b *InspectDataBuilder) Build() *InspectData {
	return &b.InspectData
}

func (d *InspectData) HasTarget(target InspectTarget) bool {
	_, exists := d.Target[target]
	return exists
}
