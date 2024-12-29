package lib

import (
	_ "embed"
	"fmt"
	"os"

	"github.com/ebitengine/purego"
)

var (
	LibinjectionSQLiFunc func(string, int, string) int
	LibinjectionXSSFunc  func(string, int) int
)

func init() {
	_, err := Load()
	if err != nil {
		panic(fmt.Sprintf("failed to load libinjection: %v", err))
	}
}

func Load() (bool, error) {
	const libinjectionSQLiSym = "libinjection_sqli"
	const LibInjectionXSSSym = "libinjection_xss"

	f, err := dumpLibinjection()
	if err != nil {
		return false, err
	}
	defer f.Close()

	handle, err := purego.Dlopen(f.Name(), purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return false, err
	}

	purego.RegisterLibFunc(&LibinjectionSQLiFunc, handle, libinjectionSQLiSym)
	purego.RegisterLibFunc(&LibinjectionXSSFunc, handle, LibInjectionXSSSym)

	return true, nil
}

// https://github.com/ebitengine/purego/issues/102
func dumpLibinjection() (*os.File, error) {
	f, err := os.CreateTemp("", "libinjection.so")
	if err != nil {
		return nil, err
	}

	if _, err := f.Write(LibinjectionSharedLib); err != nil {
		return f, err
	}

	return f, nil
}
