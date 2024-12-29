package operation

import "crypto/rand"

func generateID() string {
	s := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = s[int(b[i])%len(s)]
	}
	return string(b)
}
