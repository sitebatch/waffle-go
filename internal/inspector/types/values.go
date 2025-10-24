package types

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

type StringValue struct {
	Value string
}

func NewStringValue(value string) InspectTargetValue {
	return &StringValue{
		Value: value,
	}
}

func (v *StringValue) GetValue() string {
	return v.Value
}

func (v *StringValue) GetValues(opts ...WithGetInspectTargetValueOptions) []string {
	return []string{v.Value}
}

// KeyValues is a struct that contains key-values (map[string][]string, like http.Header and url.Values and more...) of the target.
type KeyValues struct {
	Values map[string][]string
}

func NewKeyValues(values map[string][]string) InspectTargetValue {
	return &KeyValues{
		Values: values,
	}
}

func (v *KeyValues) GetValue() string {
	// not supported for InspectTargetValueKeyValues, return empty string
	return ""
}

func (v *KeyValues) GetValues(opts ...WithGetInspectTargetValueOptions) []string {
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
