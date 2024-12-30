package application

import (
	"context"

	"github.com/sitebatch/waffle-go/internal/emitter/account_takeover"
)

// ProtectAccountTakeover protects account takeover from attacks such as brute force attack, credential stuffing
// NOTE: Login attempt statistics are stored in memory, so be aware that rate limiting may not work accurately if you are using a distributed system
func ProtectAccountTakeover(ctx context.Context, clientIP string, userID string) error {
	return account_takeover.IsSuspiciousLoginActivity(ctx, clientIP, userID)
}
