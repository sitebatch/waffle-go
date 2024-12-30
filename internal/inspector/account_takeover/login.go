package account_takeover

import (
	"fmt"
	"sync"

	"github.com/sitebatch/waffle-go/lib/limitter"
	"golang.org/x/time/rate"
)

var loginLimittersPerIPAddress = make(map[string]RateLimitter)
var loginLimittersPerIPAddressLock sync.Mutex

var loginLimittersPerUserID = make(map[string]RateLimitter)
var loginLimittersPerUserIDLock sync.Mutex

type RateLimitter interface {
	Allow() bool
}

func IsLimit(ip string, userID string, rate rate.Limit) error {
	if IsLimitedByIPAddress(ip, rate) {
		return fmt.Errorf("IP address %s is reached limit", ip)
	}

	if IsLimitedByUserID(userID, rate) {
		return fmt.Errorf("userID %s is reached limited", userID)
	}

	return nil
}

func IsLimitedByIPAddress(ip string, rate rate.Limit) bool {
	loginLimittersPerIPAddressLock.Lock()
	defer loginLimittersPerIPAddressLock.Unlock()

	if _, ok := loginLimittersPerIPAddress[ip]; !ok {
		loginLimittersPerIPAddress[ip] = limitter.NewLimitter(rate, int(rate))
	}

	return !loginLimittersPerIPAddress[ip].Allow()
}

func IsLimitedByUserID(userID string, rate rate.Limit) bool {
	loginLimittersPerUserIDLock.Lock()
	defer loginLimittersPerUserIDLock.Unlock()

	if _, ok := loginLimittersPerUserID[userID]; !ok {
		loginLimittersPerUserID[userID] = limitter.NewLimitter(rate, int(rate))
	}

	return !loginLimittersPerUserID[userID].Allow()
}

func ClearLimitByIP(ip string) {
	loginLimittersPerIPAddressLock.Lock()
	defer loginLimittersPerIPAddressLock.Unlock()

	delete(loginLimittersPerIPAddress, ip)
}

func ClearLimitByUserID(userID string) {
	loginLimittersPerUserIDLock.Lock()
	defer loginLimittersPerUserIDLock.Unlock()

	delete(loginLimittersPerUserID, userID)
}
