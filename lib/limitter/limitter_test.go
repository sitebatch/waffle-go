package limitter_test

import (
	"testing"

	"github.com/sitebatch/waffle-go/lib/limitter"
	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
)

func TestLimitter_Allow(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		rate    int
		reqSize int
		expect  bool
	}{
		"If the rate limit is 10req and 10req are sent": {
			rate:    10,
			reqSize: 9,
			expect:  true,
		},
		"If the rate limit is 10req and 11req are sent": {
			rate:    10,
			reqSize: 11,
			expect:  false,
		},
	}

	for name, tt := range testCases {
		tt := tt

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			l := limitter.NewLimitter(rate.Limit(tt.rate), tt.rate)

			for i := 0; i < tt.reqSize; i++ {
				l.Allow()
			}

			assert.Equal(t, tt.expect, l.Allow())
		})
	}
}
