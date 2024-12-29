package ssrf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsCloudMetadataServiceURL(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		url     string
		wantErr bool
	}{
		{
			url:     "http://metadata.google.internal",
			wantErr: true,
		},
		{
			url:     "https://example.com",
			wantErr: false,
		},
		{
			url:     "http://169.254.169.254",
			wantErr: true,
		},
	}

	for _, tt := range testCases {
		tt := tt

		t.Run(tt.url, func(t *testing.T) {
			t.Parallel()

			err := IsCloudMetadataServiceURL(tt.url)
			assert.Equal(t, tt.wantErr, err != nil)
		})
	}
}
