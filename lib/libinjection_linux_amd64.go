//go:build linux && amd64
// +build linux,amd64

package lib

import _ "embed"

//go:embed libinjection/linux_amd64/libinjection.so
var LibinjectionSharedLib []byte
