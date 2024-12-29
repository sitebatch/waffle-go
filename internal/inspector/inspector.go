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
	}
}

type Inspector interface {
	// Name returns the name of the inspector
	Name() InspectorName
	// Inspect inspects the given data
	// Inspector must return action.DetectionError if it detects something
	Inspect(inspectData InspectData, inspectorArgs InspectorArgs) error
	// IsSupportTarget returns whether the inspector supports the target
	IsSupportTarget(target InspectTarget) bool
}

type InspectorArgs interface {
	IsArgOf() string
}

type InspectTargetOptions struct {
	Target string
	Params []string
}
