package inspector

import (
	"github.com/sitebatch/waffle-go/action"
	"github.com/sitebatch/waffle-go/internal/inspector/account_takeover"
	"github.com/sitebatch/waffle-go/internal/inspector/types"
	"golang.org/x/time/rate"
)

type AccountTakeoverInspector struct{}
type AccountTakeoverInspectorArgs struct {
	LoginRateLimitPerSecond rate.Limit
}

func (a *AccountTakeoverInspectorArgs) IsArgOf() string {
	return string(AccountTakeoverInspectorName)
}

func NewAccountTakeoverInspector() Inspector {
	return &AccountTakeoverInspector{}
}

func (i *AccountTakeoverInspector) Name() InspectorName {
	return AccountTakeoverInspectorName
}

func (i *AccountTakeoverInspector) IsSupportTarget(target InspectTarget) bool {
	return target == InspectTargetAccountTakeover
}

func (i *AccountTakeoverInspector) Inspect(inspectData InspectData, args InspectorArgs) error {
	inspectorArgs, ok := args.(*AccountTakeoverInspectorArgs)
	if !ok {
		return nil
	}

	inspectValue := inspectData.Target[InspectTargetAccountTakeover]
	if inspectValue == nil {
		return nil
	}

	clientIP := inspectValue.GetValues(types.WithParamNames([]string{"client_ip"}))
	userID := inspectValue.GetValues(types.WithParamNames([]string{"user_id"}))

	if len(clientIP) == 0 || len(userID) == 0 {
		return nil
	}

	if err := account_takeover.IsLimit(clientIP[0], userID[0], inspectorArgs.LoginRateLimitPerSecond); err != nil {
		return &action.DetectionError{Reason: err.Error()}
	}

	return nil
}
