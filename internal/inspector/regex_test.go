package inspector_test

import (
	"net/http"
	"testing"

	"github.com/sitebatch/waffle-go/internal/inspector"
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
		expectError bool
	}{
		"when invalid args, return error": {
			arrange: arrange{
				inspectData: inspector.InspectData{
					Target: map[inspector.InspectTarget]inspector.InspectTargetValue{
						inspector.InspectTarget(inspector.InspectTargetHttpRequestURL): inspector.NewStringValue("http://malicious.com"),
					},
				},
				inspectorArgs: &inspector.LibInjectionSQLIInspectorArgs{},
			},
			expectError: true,
		},
		"inspect data has multiple targets": {
			arrange: arrange{
				inspectData: inspector.InspectData{
					Target: map[inspector.InspectTarget]inspector.InspectTargetValue{
						inspector.InspectTarget(inspector.InspectTargetHttpRequestPath): inspector.NewStringValue("/path/to/file"),
						inspector.InspectTarget(inspector.InspectTargetHttpRequestURL):  inspector.NewStringValue("http://malicious.com"),
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
			expectError: true,
		},
		"if rule has only one target and match regex, return detection error": {
			arrange: arrange{
				inspectData: inspector.InspectData{
					Target: map[inspector.InspectTarget]inspector.InspectTargetValue{
						inspector.InspectTarget(inspector.InspectTargetHttpRequestURL): inspector.NewStringValue("http://malicious.com"),
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
			expectError: true,
		},
		"if rule has only one target and not match regex, return nil": {
			arrange: arrange{
				inspectData: inspector.InspectData{
					Target: map[inspector.InspectTarget]inspector.InspectTargetValue{
						inspector.InspectTarget(inspector.InspectTargetHttpRequestURL): inspector.NewStringValue("http://example.com"),
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
		"if rule has multiple target and match regex, return error": {
			arrange: arrange{
				inspectData: inspector.InspectData{
					Target: map[inspector.InspectTarget]inspector.InspectTargetValue{
						inspector.InspectTarget(inspector.InspectTargetHttpRequestURL):  inspector.NewStringValue("http://malicious.com"),
						inspector.InspectTarget(inspector.InspectTargetHttpRequestPath): inspector.NewStringValue("/path/to/file"),
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
			expectError: true,
		},
		"if rule has key option and match regex, return error": {
			arrange: arrange{
				inspectData: inspector.InspectData{
					Target: map[inspector.InspectTarget]inspector.InspectTargetValue{
						inspector.InspectTarget(inspector.InspectTargetHttpRequestHeader): inspector.NewKeyValues(http.Header{
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
			expectError: true,
		},
		"if rule has key option and not match regex, return nil": {
			arrange: arrange{
				inspectData: inspector.InspectData{
					Target: map[inspector.InspectTarget]inspector.InspectTargetValue{
						inspector.InspectTarget(inspector.InspectTargetHttpRequestHeader): inspector.NewKeyValues(http.Header{
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
		"if rule has key option, but has not key in inspect data, return nil": {
			arrange: arrange{
				inspectData: inspector.InspectData{
					Target: map[inspector.InspectTarget]inspector.InspectTargetValue{
						inspector.InspectTarget(inspector.InspectTargetHttpRequestHeader): inspector.NewKeyValues(http.Header{
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
		tt := tt
		t.Run(name, func(t *testing.T) {
			inspector := inspector.NewRegexInspector()
			err := inspector.Inspect(tt.arrange.inspectData, tt.arrange.inspectorArgs)
			if tt.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
		})
	}
}
