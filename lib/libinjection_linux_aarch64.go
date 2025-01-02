//go:build linux && arm64
// +build linux,arm64

package lib

import _ "embed"

//go:embed libinjection/linux_aarch64/libinjection.so
var LibinjectionSharedLib []byte
