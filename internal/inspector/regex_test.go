package inspector_test

import (
	"net/http"
	"testing"

	"github.com/sitebatch/waffle-go/internal/inspector"
	"github.com/sitebatch/waffle-go/internal/inspector/types"
	"github.com/stretchr/testify/assert"
)

func TestRegexInspector_Inspect(t *testing.T) {
	t.Parallel()

	type arrange struct {
		inspectData   inspector.InspectData
		inspectorArgs inspector.InspectorArgs
	}

	testCases := map[string]struct {
		arrange
		suspiciousPayload string
		expectError       bool
	}{
		"when invalid args, return error": {
			arrange: arrange{
				inspectData: inspector.InspectData{
					Target: map[inspector.InspectTarget]types.InspectTargetValue{
						inspector.InspectTarget(inspector.InspectTargetHttpRequestURL): types.NewStringValue("http://malicious.com"),
					},
				},
				inspectorArgs: &inspector.LibInjectionSQLIInspectorArgs{},
			},
			expectError: true,
		},
		"inspect data has multiple targets": {
			arrange: arrange{
				inspectData: inspector.InspectData{
					Target: map[inspector.InspectTarget]types.InspectTargetValue{
						inspector.InspectTarget(inspector.InspectTargetHttpRequestPath): types.NewStringValue("/path/to/file"),
						inspector.InspectTarget(inspector.InspectTargetHttpRequestURL):  types.NewStringValue("http://malicious.com"),
					},
				},
				inspectorArgs: &inspector.RegexInspectorArgs{
					Regex: "^http://malicious.com$",
					InspectTargetOptions: []inspector.InspectTargetOptions{
						{
							Target: inspector.InspectTargetHttpRequestURL.String(),
						},
					},
				},
			},
			suspiciousPayload: "http://malicious.com",
			expectError:       false,
		},
		"rule has an target and match regex": {
			arrange: arrange{
				inspectData: inspector.InspectData{
					Target: map[inspector.InspectTarget]types.InspectTargetValue{
						inspector.InspectTarget(inspector.InspectTargetHttpRequestURL): types.NewStringValue("http://malicious.com"),
					},
				},
				inspectorArgs: &inspector.RegexInspectorArgs{
					Regex: "^http://malicious.com$",
					InspectTargetOptions: []inspector.InspectTargetOptions{
						{
							Target: inspector.InspectTargetHttpRequestURL.String(),
						},
					},
				},
			},
			suspiciousPayload: "http://malicious.com",
			expectError:       false,
		},
		"rule has an target, but not match regex": {
			arrange: arrange{
				inspectData: inspector.InspectData{
					Target: map[inspector.InspectTarget]types.InspectTargetValue{
						inspector.InspectTarget(inspector.InspectTargetHttpRequestURL): types.NewStringValue("http://example.com"),
					},
				},
				inspectorArgs: &inspector.RegexInspectorArgs{
					Regex: "^http://malicious.com$",
					InspectTargetOptions: []inspector.InspectTargetOptions{
						{
							Target: inspector.InspectTargetHttpRequestURL.String(),
						},
					},
				},
			},
			expectError: false,
		},
		"rule has multiple targets and match regex": {
			arrange: arrange{
				inspectData: inspector.InspectData{
					Target: map[inspector.InspectTarget]types.InspectTargetValue{
						inspector.InspectTarget(inspector.InspectTargetHttpRequestURL):  types.NewStringValue("http://malicious.com"),
						inspector.InspectTarget(inspector.InspectTargetHttpRequestPath): types.NewStringValue("/path/to/file"),
					},
				},
				inspectorArgs: &inspector.RegexInspectorArgs{
					Regex: "^http://malicious.com$",
					InspectTargetOptions: []inspector.InspectTargetOptions{
						{
							Target: inspector.InspectTargetHttpRequestPath.String(),
						},
						{
							Target: inspector.InspectTargetHttpRequestURL.String(),
						},
					},
				},
			},
			suspiciousPayload: "http://malicious.com",
			expectError:       false,
		},
		"rule has key option and match regex": {
			arrange: arrange{
				inspectData: inspector.InspectData{
					Target: map[inspector.InspectTarget]types.InspectTargetValue{
						inspector.InspectTarget(inspector.InspectTargetHttpRequestHeader): types.NewKeyValues(http.Header{
							"User-Agent": []string{"Chrome", "Firefox"},
						}),
					},
				},
				inspectorArgs: &inspector.RegexInspectorArgs{
					Regex: "^Firefox$",
					InspectTargetOptions: []inspector.InspectTargetOptions{
						{
							Target: inspector.InspectTargetHttpRequestHeader.String(),
							Params: []string{"User-Agent"},
						},
					},
				},
			},
			suspiciousPayload: "Firefox",
			expectError:       false,
		},
		"rule has key option and not match regex": {
			arrange: arrange{
				inspectData: inspector.InspectData{
					Target: map[inspector.InspectTarget]types.InspectTargetValue{
						inspector.InspectTarget(inspector.InspectTargetHttpRequestHeader): types.NewKeyValues(http.Header{
							"User-Agent": []string{"Chrome", "Firefox"},
						}),
					},
				},
				inspectorArgs: &inspector.RegexInspectorArgs{
					Regex: "^Edge$",
					InspectTargetOptions: []inspector.InspectTargetOptions{
						{
							Target: inspector.InspectTargetHttpRequestHeader.String(),
							Params: []string{"User-Agent"},
						},
					},
				},
			},
			expectError: false,
		},
		"rule has key option, but has not key in inspect data": {
			arrange: arrange{
				inspectData: inspector.InspectData{
					Target: map[inspector.InspectTarget]types.InspectTargetValue{
						inspector.InspectTarget(inspector.InspectTargetHttpRequestHeader): types.NewKeyValues(http.Header{
							"Host": []string{"example.com"},
						}),
					},
				},
				inspectorArgs: &inspector.RegexInspectorArgs{
					Regex: "^example.com$",
					InspectTargetOptions: []inspector.InspectTargetOptions{
						{
							Target: inspector.InspectTargetHttpRequestHeader.String(),
							Params: []string{"User-Agent"},
						},
					},
				},
			},
			expectError: false,
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			inspector := inspector.NewRegexInspector()
			suspicious, err := inspector.Inspect(tt.arrange.inspectData, tt.arrange.inspectorArgs)
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, suspicious)
				return
			}

			if tt.suspiciousPayload == "" {
				assert.Nil(t, suspicious)
				assert.NoError(t, err)
				return
			}

			assert.NotNil(t, suspicious)
			assert.Equal(t, tt.suspiciousPayload, suspicious.Payload)
			assert.NoError(t, err)
		})
	}
}
