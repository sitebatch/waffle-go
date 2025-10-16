package waf

import (
	"sync"

	"github.com/sitebatch/waffle-go/internal/operation"
)

type EventRecorder struct {
	events ReadOnlyDetectionEvents
	mu     sync.Mutex
}

func NewEventRecorder() *EventRecorder {
	return &EventRecorder{
		events: nil,
		mu:     sync.Mutex{},
	}
}

func (er *EventRecorder) Store(events ReadOnlyDetectionEvents) {
	er.mu.Lock()
	defer er.mu.Unlock()

	er.events = events
}

func (er *EventRecorder) Load() ReadOnlyDetectionEvents {
	er.mu.Lock()
	defer er.mu.Unlock()

	return er.events
}

func (er *EventRecorder) Clear() {
	er.mu.Lock()
	defer er.mu.Unlock()

	er.events = nil
}

// snapshot is an event of a waf detection state at a particular operation.
// It is used as a read-only representation of that state.
type snapshot struct {
	operation operation.Operation
	events    []DetectionEvent
}

var _ ReadOnlyDetectionEvents = (*snapshot)(nil)

func (s *snapshot) Events() []DetectionEvent {
	return s.events
}

func (s *snapshot) Operation() operation.Operation {
	return s.operation
}
