// Package limtiter provides a simple rate limit using x/time/limit.
// It is mainly intended for use in fraudulent login detection, such as credential stuffing.
package limitter

import (
	"golang.org/x/time/rate"
)

type Limitter interface {
	Allow() bool
}

type SimpleLimitter struct {
	limiter *rate.Limiter
}

func NewLimitter(r rate.Limit, burst int) Limitter {
	return &SimpleLimitter{
		limiter: rate.NewLimiter(r, burst),
	}
}

func (l *SimpleLimitter) Allow() bool {
	return l.limiter.Allow()
}
