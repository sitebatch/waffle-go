package inspector

import (
	"github.com/sitebatch/waffle-go/internal/log"
)

type GetInspectTargetValueOptions struct {
	ParamNames []string
}

type WithGetInspectTargetValueOptions func(o *GetInspectTargetValueOptions)

func WithParamNames(paramNames []string) WithGetInspectTargetValueOptions {
	return func(o *GetInspectTargetValueOptions) {
		o.ParamNames = paramNames
	}
}

type InspectTargetValue interface {
	// GetValue returns the value of the target
	GetValue() string
	// GetValues returns the values of the target.
	// If keys are provided, it returns the values of the keys. If keys are not provided, it returns all values.
	GetValues(opts ...WithGetInspectTargetValueOptions) []string
}

type InspectTargetValueString struct {
	Value string
}

func NewInspectTargetValueString(value string) InspectTargetValue {
	return &InspectTargetValueString{
		Value: value,
	}
}

func (v *InspectTargetValueString) GetValue() string {
	return v.Value
}

func (v *InspectTargetValueString) GetValues(opts ...WithGetInspectTargetValueOptions) []string {
	return []string{v.Value}
}

// InspectTargetValueKeyValues is a struct that contains key-values (map[string][]string, like http.Header and url.Values and more...) of the target.
type InspectTargetValueKeyValues struct {
	Values map[string][]string
}

func NewInspectTargetValueKeyValues(values map[string][]string) InspectTargetValue {
	return &InspectTargetValueKeyValues{
		Values: values,
	}
}

func (v *InspectTargetValueKeyValues) GetValue() string {
	log.Error("GetValue() is not supported for InspectTargetValueKeyValues, return empty string")
	return ""
}

func (v *InspectTargetValueKeyValues) GetValues(opts ...WithGetInspectTargetValueOptions) []string {
	o := &GetInspectTargetValueOptions{}

	for _, opt := range opts {
		opt(o)
	}

	var values []string

	if len(o.ParamNames) == 0 {
		for _, v := range v.Values {
			values = append(values, v...)
		}
		return values
	}

	for _, name := range o.ParamNames {
		if v.Values[name] == nil {
			continue
		}

		values = append(values, v.Values[name]...)
	}

	return values
}
