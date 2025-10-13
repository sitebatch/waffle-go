package waf

import "sync/atomic"

type EventRecorder struct {
	events *atomic.Value
}

func NewEventRecorder() *EventRecorder {
	v := &atomic.Value{}
	v.Store(&snapshot{})
	return &EventRecorder{
		events: v,
	}
}

func (er *EventRecorder) Store(events *snapshot) {
	er.events.Store(events)
}

func (er *EventRecorder) Load() ReadOnlyDetectionEvents {
	v := er.events.Load().(*snapshot)
	return v
}

func (er *EventRecorder) Clear() {
	er.events.Store(&snapshot{})
}
