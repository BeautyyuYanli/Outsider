package proto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"strings"
)

const contextDomain = "outsider-ctx-v1"

// Context is the signed human-readable request context.
type Context struct {
	Name           string `json:"name"`
	Reason         string `json:"reason"`
	CommandSummary string `json:"command_summary"`
}

func appendEncodedString(dst []byte, s string) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(s)))
	dst = append(dst, lenBuf[:]...)
	return append(dst, s...)
}

// EncodeContextBytes encodes context with deterministic length-prefixed binary encoding.
func EncodeContextBytes(ctx Context) []byte {
	size := len(contextDomain) + 1 + 12 + len(ctx.Name) + len(ctx.Reason) + len(ctx.CommandSummary)
	buf := make([]byte, 0, size)
	buf = append(buf, contextDomain...)
	buf = append(buf, 0x00)
	buf = appendEncodedString(buf, ctx.Name)
	buf = appendEncodedString(buf, ctx.Reason)
	buf = appendEncodedString(buf, ctx.CommandSummary)
	return buf
}

// ComputeContextHash returns SHA-256(EncodeContextBytes(ctx)).
func ComputeContextHash(ctx Context) [32]byte {
	return sha256.Sum256(EncodeContextBytes(ctx))
}

// SlugifyName normalizes a secret name into a safe URL path segment for Bitwarden prefix matching.
func SlugifyName(name string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevDash = false
		} else if b.Len() > 0 && !prevDash {
			b.WriteByte('-')
			prevDash = true
		}
	}
	s := strings.Trim(b.String(), "-")
	if len(s) > 64 {
		s = strings.TrimRight(s[:64], "-")
	}
	if s == "" {
		return "secret"
	}
	return s
}

// RandomToken generates a cryptographically random Base64URL (no padding) token with n random bytes.
func RandomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
