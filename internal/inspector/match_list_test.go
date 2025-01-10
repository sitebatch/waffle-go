package inspector_test

import (
	"testing"

	"github.com/sitebatch/waffle-go/action"
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
		detected bool
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
			detected: true,
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
			detected: false,
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
			detected: true,
		},
	}

	for name, tc := range testCases {
		tc := tc

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			matchListInspector := inspector.NewMatchListInspector()
			err := matchListInspector.Inspect(tc.arrange.inspectData, tc.arrange.inspectorArgs)

			if tc.detected {
				assert.Error(t, err)
				var detectionError *action.DetectionError
				assert.ErrorAs(t, err, &detectionError)
				return
			}

			assert.NoError(t, err)
		})
	}

}
