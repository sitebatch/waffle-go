package inspector

import (
	"github.com/sitebatch/waffle-go/internal/inspector/sqli"
)

type SQLiInspector struct{}

type SQLiInspectorArgs struct {
}

func (r *SQLiInspectorArgs) IsArgOf() string {
	return string(SQLiInspectorName)
}

func NewSQLiInspector() Inspector {
	return &SQLiInspector{}
}

func (r *SQLiInspector) Name() InspectorName {
	return SQLiInspectorName
}

func (r *SQLiInspector) IsSupportTarget(target InspectTarget) bool {
	return target == InspectTargetSQLQuery
}

func (r *SQLiInspector) Inspect(inspectData InspectData, inspectorArgs InspectorArgs) (*SuspiciousResult, error) {
	inspectValue := inspectData.Target[InspectTargetSQLQuery]

	if inspectValue == nil {
		return nil, nil
	}

	query := inspectValue.GetValue()

	isSQLi, err := sqli.IsWhereTautologyFull(query)
	if err != nil {
		return nil, err
	}

	if isSQLi {
		return &SuspiciousResult{
			Payload: query,
			Message: "detected sql injection, because of where tautology",
		}, nil
	}

	if err = sqli.IsQueryCommentInjection(query); err != nil {
		return &SuspiciousResult{
			Payload: query,
			Message: "detectd sql injection, because of query comment injection",
		}, nil
	}

	return nil, nil
}
