package waf

import (
	"sync"
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
