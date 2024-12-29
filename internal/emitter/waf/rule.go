package waf

import (
	"github.com/sitebatch/waffle-go/internal/inspector"
	"github.com/sitebatch/waffle-go/internal/rule"
)

func ToInspectTargetOptions(inspectTargets []rule.InspectTarget) []inspector.InspectTargetOptions {
	inspectTargetOptions := make([]inspector.InspectTargetOptions, len(inspectTargets))

	for _, inspectTarget := range inspectTargets {
		inspectTargetOptions = append(inspectTargetOptions, inspector.InspectTargetOptions{
			Target: inspectTarget.Target,
			Params: inspectTarget.Keys,
		})
	}

	return inspectTargetOptions
}
