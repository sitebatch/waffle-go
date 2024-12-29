//go:build darwin && arm64
// +build darwin,arm64

package lib

import _ "embed"

//go:embed vendor/libinjection/darwin_aarch64/libinjection.so
var LibinjectionSharedLib []byte
