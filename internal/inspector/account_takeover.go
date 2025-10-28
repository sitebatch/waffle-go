package inspector

import (
	"fmt"

	"github.com/sitebatch/waffle-go/internal/inspector/account_takeover"
	"github.com/sitebatch/waffle-go/internal/inspector/types"
	"golang.org/x/time/rate"
)

type AccountTakeoverInspector struct{}
type AccountTakeoverInspectorArgs struct {
	LoginRateLimitPerSecond rate.Limit
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

func (i *AccountTakeoverInspector) Inspect(inspectData InspectData, args InspectorArgs) (*InspectResult, error) {
	inspectValue := inspectData.Target[InspectTargetAccountTakeover]
	if inspectValue == nil {
		return nil, nil
	}

	clientIP := inspectValue.GetValues(types.WithParamNames([]string{"client_ip"}))
	userID := inspectValue.GetValues(types.WithParamNames([]string{"user_id"}))

	if len(clientIP) == 0 || len(userID) == 0 {
		return nil, nil
	}

	if err := account_takeover.IsLimit(clientIP[0], userID[0], args.AccountTakeoverInspectorArgs.LoginRateLimitPerSecond); err != nil {
		return &InspectResult{
			Target:  InspectTargetAccountTakeover,
			Payload: fmt.Sprintf("client_ip: %s, user_id: %s", clientIP[0], userID[0]),
			Message: err.Error(),
		}, nil
	}

	return nil, nil
}
