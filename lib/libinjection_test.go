package lib_test

import (
	"testing"

	"github.com/sitebatch/waffle-go/lib"
	"github.com/stretchr/testify/assert"
)

func TestLoad(t *testing.T) {
	t.Parallel()

	load, err := lib.Load()
	assert.NoError(t, err)
	assert.True(t, load)
}

func TestLibinjectionSQLiFunc(t *testing.T) {
	t.Parallel()

	load, err := lib.Load()
	assert.NoError(t, err)
	assert.True(t, load)

	testCases := []struct {
		q      string
		isSQLi int
	}{
		{
			q:      "-1' and 1=1 union/* foo */select load_file('/etc/passwd')--",
			isSQLi: 1,
		},
		{
			q:      "1=1",
			isSQLi: 0,
		},
	}

	for _, tt := range testCases {
		tt := tt

		t.Run(tt.q, func(t *testing.T) {
			t.Parallel()

			var fingerprint string
			assert.Equal(t, tt.isSQLi, lib.LibinjectionSQLiFunc(tt.q, len(tt.q), fingerprint))
		})
	}
}

func TestLibinjectionXSSFunc(t *testing.T) {
	t.Parallel()

	load, err := lib.Load()
	assert.NoError(t, err)
	assert.True(t, load)

	testCases := []struct {
		q     string
		isXSS int
	}{
		{
			q:     "<script>alert(1)</script>",
			isXSS: 1,
		},
		{
			q:     "script",
			isXSS: 0,
		},
	}

	for _, tt := range testCases {
		tt := tt

		t.Run(tt.q, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.isXSS, lib.LibinjectionXSSFunc(tt.q, len(tt.q)))
		})
	}
}
