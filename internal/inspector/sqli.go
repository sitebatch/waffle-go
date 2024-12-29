package inspector

import (
	"github.com/sitebatch/waffle-go/internal/action"
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

func (r *SQLiInspector) Inspect(inspectData InspectData, inspectorArgs InspectorArgs) error {
	inspectValue := inspectData.Target[InspectTargetSQLQuery]

	if inspectValue == nil {
		return nil
	}

	query := inspectValue.GetValue()

	isSQLi, err := sqli.IsWhereTautologyFull(query)
	if err != nil {
		return err
	}

	if isSQLi {
		return &action.DetectionError{Reason: "detected sql injection, because of where tautology"}
	}

	if err = sqli.IsQueryCommentInjection(query); err != nil {
		return &action.DetectionError{Reason: "detectd sql injection, because of query comment injection"}
	}

	return nil
}
