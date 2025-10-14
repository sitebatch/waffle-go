package inspector

type InspectorName string

var (
	RegexInspectorName            InspectorName = "RegexInspector"
	MatchListInspectorName        InspectorName = "MatchListInspector"
	LibInjectionSQLIInspectorName InspectorName = "LibInjectionSQLIInspector"
	LibInjectionXSSInspectorName  InspectorName = "LibInjectionXSSInspector"
	SQLiInspectorName             InspectorName = "SQLiInspector"
	LFIInspectorName              InspectorName = "LFIInspector"
	SSRFInspectorName             InspectorName = "SSRFInspector"
	AccountTakeoverInspectorName  InspectorName = "AccountTakeoverInspector"
)

func NewInspector() map[string]Inspector {
	return map[string]Inspector{
		string("regex"):             NewRegexInspector(),
		string("match_list"):        NewMatchListInspector(),
		string("libinjection_sqli"): NewLibInjectionSQLIInspector(),
		string("libinjection_xss"):  NewLibInjectionXSSInspector(),
		string("sqli"):              NewSQLiInspector(),
		string("lfi"):               NewLFIInspector(),
		string("ssrf"):              NewSSRFInspector(),
		string("account_takeover"):  NewAccountTakeoverInspector(),
	}
}

type Inspector interface {
	// Name returns the name of the inspector
	Name() InspectorName
	// Inspect inspects the given data
	// Returns SuspiciousResult if the inspected data is determined to be an attack, otherwise returns nil
	// If an error occurs during inspection, returns an error
	Inspect(inspectData InspectData, inspectorArgs InspectorArgs) (*InspectResult, error)
	// IsSupportTarget returns whether the inspector supports the target
	IsSupportTarget(target InspectTarget) bool
}

type InspectorArgs interface {
	IsArgOf() string
}

type InspectTargetOptions struct {
	Target InspectTarget
	Params []string
}

// InspectResult represents the result of an inspection
type InspectResult struct {
	Target  InspectTarget // the target that was inspected
	Payload string        // the payload deemed suspicious
	Message string        // message describing why it is suspicious
}
