package waf

import "github.com/sitebatch/waffle-go/internal/operation"

// snapshot is an event of a waf detection state at a particular operation.
// It is used as a read-only representation of that state.
type snapshot struct {
	events    []DetectionEvent
	operation operation.Operation
}

var _ ReadOnlyDetectionEvents = (*snapshot)(nil)

func (s *snapshot) Events() []DetectionEvent {
	return s.events
}

func (s *snapshot) Operation() operation.Operation {
	return s.operation
}
