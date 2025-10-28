package inspector

type InspectorName string

const (
	RegexInspectorName            InspectorName = "regex"
	MatchListInspectorName        InspectorName = "match_list"
	LibInjectionSQLIInspectorName InspectorName = "libinjection_sqli"
	LibInjectionXSSInspectorName  InspectorName = "libinjection_xss"
	SQLiInspectorName             InspectorName = "sqli"
	LFIInspectorName              InspectorName = "lfi"
	SSRFInspectorName             InspectorName = "ssrf"
	AccountTakeoverInspectorName  InspectorName = "account_takeover"
)

func NewInspectors() map[InspectorName]Inspector {
	return map[InspectorName]Inspector{
		RegexInspectorName:            NewRegexInspector(),
		MatchListInspectorName:        NewMatchListInspector(),
		LibInjectionSQLIInspectorName: NewLibInjectionSQLIInspector(),
		LibInjectionXSSInspectorName:  NewLibInjectionXSSInspector(),
		SQLiInspectorName:             NewSQLiInspector(),
		LFIInspectorName:              NewLFIInspector(),
		SSRFInspectorName:             NewSSRFInspector(),
		AccountTakeoverInspectorName:  NewAccountTakeoverInspector(),
	}
}

type InspectorArgs struct {
	TargetOptions []InspectTargetOptions

	RegexInspectorArgs           RegexInspectorArgs
	MatchListInspectorArgs       MatchListInspectorArgs
	AccountTakeoverInspectorArgs AccountTakeoverInspectorArgs
}

type InspectTargetOptions struct {
	Target InspectTarget
	Params []string
}

type Inspector interface {
	// Inspect inspects the given data
	// Returns SuspiciousResult if the inspected data is determined to be an attack, otherwise returns nil
	// If an error occurs during inspection, returns an error
	Inspect(inspectData InspectData, inspectorArgs InspectorArgs) (*InspectResult, error)
	// IsSupportTarget returns whether the inspector supports the target
	IsSupportTarget(target InspectTarget) bool
}

// InspectResult represents the result of an inspection
type InspectResult struct {
	Target  InspectTarget // the target that was inspected
	Payload string        // the payload deemed suspicious
	Message string        // message describing why it is suspicious
}
