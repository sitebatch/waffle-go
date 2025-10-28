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
		"inspect data has multiple targets": {
			arrange: arrange{
				inspectData: inspector.InspectData{
					Target: map[inspector.InspectTarget]types.InspectTargetValue{
						inspector.InspectTargetHttpRequestPath: types.NewStringValue("/path/to/file"),
						inspector.InspectTargetHttpRequestURL:  types.NewStringValue("http://malicious.com"),
					},
				},
				inspectorArgs: inspector.InspectorArgs{
					Regex: "^http://malicious.com$",
					TargetOptions: []inspector.InspectTargetOptions{
						{
							Target: inspector.InspectTargetHttpRequestURL,
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
						inspector.InspectTargetHttpRequestURL: types.NewStringValue("http://malicious.com"),
					},
				},
				inspectorArgs: inspector.InspectorArgs{
					Regex: "^http://malicious.com$",
					TargetOptions: []inspector.InspectTargetOptions{
						{
							Target: inspector.InspectTargetHttpRequestURL,
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
						inspector.InspectTargetHttpRequestURL: types.NewStringValue("http://example.com"),
					},
				},
				inspectorArgs: inspector.InspectorArgs{
					Regex: "^http://malicious.com$",
					TargetOptions: []inspector.InspectTargetOptions{
						{
							Target: inspector.InspectTargetHttpRequestURL,
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
						inspector.InspectTargetHttpRequestURL:  types.NewStringValue("http://malicious.com"),
						inspector.InspectTargetHttpRequestPath: types.NewStringValue("/path/to/file"),
					},
				},
				inspectorArgs: inspector.InspectorArgs{
					Regex: "^http://malicious.com$",
					TargetOptions: []inspector.InspectTargetOptions{
						{
							Target: inspector.InspectTargetHttpRequestPath,
						},
						{
							Target: inspector.InspectTargetHttpRequestURL,
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
						inspector.InspectTargetHttpRequestHeader: types.NewKeyValues(http.Header{
							"User-Agent": []string{"Chrome", "Firefox"},
						}),
					},
				},
				inspectorArgs: inspector.InspectorArgs{
					Regex: "^Firefox$",
					TargetOptions: []inspector.InspectTargetOptions{
						{
							Target: inspector.InspectTargetHttpRequestHeader,
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
						inspector.InspectTargetHttpRequestHeader: types.NewKeyValues(http.Header{
							"User-Agent": []string{"Chrome", "Firefox"},
						}),
					},
				},
				inspectorArgs: inspector.InspectorArgs{
					Regex: "^Edge$",
					TargetOptions: []inspector.InspectTargetOptions{
						{
							Target: inspector.InspectTargetHttpRequestHeader,
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
						inspector.InspectTargetHttpRequestHeader: types.NewKeyValues(http.Header{
							"Host": []string{"example.com"},
						}),
					},
				},
				inspectorArgs: inspector.InspectorArgs{
					Regex: "^example.com$",
					TargetOptions: []inspector.InspectTargetOptions{
						{
							Target: inspector.InspectTargetHttpRequestHeader,
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
