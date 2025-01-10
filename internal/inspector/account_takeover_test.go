package inspector_test

import (
	"math/rand"
	"net"
	"testing"

	"github.com/google/uuid"
	"github.com/sitebatch/waffle-go/action"
	"github.com/sitebatch/waffle-go/internal/inspector"
	"github.com/sitebatch/waffle-go/internal/inspector/types"
	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
)

func TestAccountTakeoverInspector_Inspect(t *testing.T) {
	type arrange struct {
		inspectData   inspector.InspectData
		inspectorArgs inspector.InspectorArgs
	}

	testCases := map[string]struct {
		arrange
		randomizeTo string
		reqSize     int
		detected    bool
	}{
		"single IP address that make a lot of login request": {
			arrange: arrange{
				inspectData: inspector.InspectData{
					Target: map[inspector.InspectTarget]types.InspectTargetValue{
						inspector.InspectTargetAccountTakeover: types.NewKeyValues(
							map[string][]string{
								"client_ip": {"192.168.1.1"},
								"user_id":   {generateDummyUserID(t)},
							},
						),
					},
				},
				inspectorArgs: &inspector.AccountTakeoverInspectorArgs{
					LoginRateLimitPerSecond: rate.Limit(10),
				},
			},
			randomizeTo: "user_id",
			reqSize:     11,
			detected:    true,
		},
		"single user id that make a lot of login request": {
			arrange: arrange{
				inspectData: inspector.InspectData{
					Target: map[inspector.InspectTarget]types.InspectTargetValue{
						inspector.InspectTargetAccountTakeover: types.NewKeyValues(
							map[string][]string{
								"client_ip": {generateDummyIP(t)},
								"user_id":   {"user@example.com"},
							},
						),
					},
				},
				inspectorArgs: &inspector.AccountTakeoverInspectorArgs{
					LoginRateLimitPerSecond: rate.Limit(10),
				},
			},
			randomizeTo: "client_ip",
			reqSize:     11,
			detected:    true,
		},
		"single IP address no reache limit": {
			arrange: arrange{
				inspectData: inspector.InspectData{
					Target: map[inspector.InspectTarget]types.InspectTargetValue{
						inspector.InspectTargetAccountTakeover: types.NewKeyValues(
							map[string][]string{
								"client_ip": {"10.0.1.1"},
								"user_id":   {generateDummyUserID(t)},
							},
						),
					},
				},
				inspectorArgs: &inspector.AccountTakeoverInspectorArgs{
					LoginRateLimitPerSecond: rate.Limit(10),
				},
			},
			randomizeTo: "user_id",
			reqSize:     5,
			detected:    false,
		},
		"single user id no reache limit": {
			arrange: arrange{
				inspectData: inspector.InspectData{
					Target: map[inspector.InspectTarget]types.InspectTargetValue{
						inspector.InspectTargetAccountTakeover: types.NewKeyValues(
							map[string][]string{
								"client_ip": {generateDummyIP(t)},
								"user_id":   {"user@example.jp"},
							},
						),
					},
				},
				inspectorArgs: &inspector.AccountTakeoverInspectorArgs{
					LoginRateLimitPerSecond: rate.Limit(10),
				},
			},
			randomizeTo: "client_ip",
			reqSize:     5,
			detected:    false,
		},
	}

	for name, tt := range testCases {
		tt := tt

		t.Run(name, func(t *testing.T) {
			var err error
			for i := 0; i < tt.reqSize; i++ {
				i := inspector.NewAccountTakeoverInspector()

				if tt.randomizeTo == "client_ip" {
					tt.arrange.inspectData.Target[inspector.InspectTargetAccountTakeover].(*types.KeyValues).Values["client_ip"][0] = generateDummyIP(t)
				}

				if tt.randomizeTo == "user_id" {
					tt.arrange.inspectData.Target[inspector.InspectTargetAccountTakeover].(*types.KeyValues).Values["user_id"][0] = generateDummyUserID(t)
				}

				err = i.Inspect(tt.arrange.inspectData, tt.arrange.inspectorArgs)
			}

			if tt.detected {
				assert.Error(t, err)

				var detectionError *action.DetectionError
				assert.ErrorAs(t, err, &detectionError)
				return
			}

			assert.NoError(t, err)
		})
	}
}

func generateDummyUserID(t *testing.T) string {
	t.Helper()

	return uuid.New().String()
}

func generateDummyIP(t *testing.T) string {
	t.Helper()

	size := 4
	ip := make([]byte, size)
	for i := 0; i < size; i++ {
		ip[i] = byte(rand.Intn(256))
	}
	return net.IP(ip).To4().String()
}
