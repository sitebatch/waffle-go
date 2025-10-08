package inspector_test

import (
	"testing"

	"github.com/sitebatch/waffle-go/internal/inspector"
	"github.com/sitebatch/waffle-go/internal/inspector/types"
	"github.com/stretchr/testify/assert"
)

func TestMatchlistInspector_Inspect(t *testing.T) {
	t.Parallel()

	type arrange struct {
		inspectData   inspector.InspectData
		inspectorArgs inspector.InspectorArgs
	}

	testCases := map[string]struct {
		arrange
		suspiciousPayload string
	}{
		"when match return detection error": {
			arrange: arrange{
				inspectData: inspector.InspectData{
					Target: map[inspector.InspectTarget]types.InspectTargetValue{
						inspector.InspectTarget(inspector.InspectTargetHttpRequestQuery): types.NewStringValue("q=/etc/passwd"),
					},
				},
				inspectorArgs: &inspector.MatchListInspectorArgs{
					List: []string{"etc/test", "etc/passwd", "etc/hosts"},
					InspectTargetOptions: []inspector.InspectTargetOptions{
						{
							Target: inspector.InspectTargetHttpRequestQuery.String(),
						},
					},
				},
			},
			suspiciousPayload: "q=/etc/passwd",
		},
		"when not match return nil": {
			arrange: arrange{
				inspectData: inspector.InspectData{
					Target: map[inspector.InspectTarget]types.InspectTargetValue{
						inspector.InspectTarget(inspector.InspectTargetHttpRequestQuery): types.NewStringValue("q=/etc/passwd"),
					},
				},
				inspectorArgs: &inspector.MatchListInspectorArgs{
					List: []string{"etc/test", "etc/shadow", "etc/hosts"},
					InspectTargetOptions: []inspector.InspectTargetOptions{
						{
							Target: inspector.InspectTargetHttpRequestQuery.String(),
						},
					},
				},
			},
		},
		"when multiple targets": {
			arrange: arrange{
				inspectData: inspector.InspectData{
					Target: map[inspector.InspectTarget]types.InspectTargetValue{
						inspector.InspectTarget(inspector.InspectTargetHttpRequestQuery): types.NewStringValue("q=/etc/passwd"),
					},
				},
				inspectorArgs: &inspector.MatchListInspectorArgs{
					List: []string{"etc/test", "etc/passwd", "etc/hosts"},
					InspectTargetOptions: []inspector.InspectTargetOptions{
						{
							Target: inspector.InspectTargetHttpRequestURL.String(),
						},
						{
							Target: inspector.InspectTargetHttpRequestQuery.String(),
						},
					},
				},
			},
			suspiciousPayload: "q=/etc/passwd",
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			matchListInspector := inspector.NewMatchListInspector()
			suspicious, err := matchListInspector.Inspect(tt.arrange.inspectData, tt.arrange.inspectorArgs)

			if tt.suspiciousPayload != "" {
				assert.NoError(t, err)
				assert.Equal(t, tt.suspiciousPayload, suspicious.Payload)
				return
			}

			assert.NoError(t, err)
		})
	}

}
