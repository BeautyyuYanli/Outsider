package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	contextDomain     = "outsider-ctx-v1"
	requestDomain     = "outsider-req-v1"
	fingerprintDomain = "outsider-id-fp-v1"
)

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

// BuildSignInput constructs the exact 140-byte Ed25519 signing payload.
func BuildSignInput(idPk, pkReq, contextHash []byte, requestTs int64, ttlSecs uint32, nonce []byte) ([]byte, error) {
	if len(idPk) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("id_pk must be %d bytes, got %d", ed25519.PublicKeySize, len(idPk))
	}
	if len(pkReq) != 32 {
		return nil, fmt.Errorf("pk_req must be 32 bytes, got %d", len(pkReq))
	}
	if len(contextHash) != 32 {
		return nil, fmt.Errorf("context_hash must be 32 bytes, got %d", len(contextHash))
	}
	if len(nonce) != 16 {
		return nil, fmt.Errorf("request_nonce must be 16 bytes, got %d", len(nonce))
	}
	if requestTs < 0 {
		return nil, errors.New("request_ts must be non-negative")
	}

	buf := make([]byte, 0, len(requestDomain)+1+32+32+32+8+4+16)
	buf = append(buf, requestDomain...)
	buf = append(buf, 0x00)
	buf = append(buf, idPk...)
	buf = append(buf, pkReq...)
	buf = append(buf, contextHash...)

	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(requestTs))
	buf = append(buf, tsBuf[:]...)

	var ttlBuf [4]byte
	binary.BigEndian.PutUint32(ttlBuf[:], ttlSecs)
	buf = append(buf, ttlBuf[:]...)

	buf = append(buf, nonce...)
	return buf, nil
}

// VerifyRequestSignature validates all wire encodings and verifies the Ed25519 signature.
func VerifyRequestSignature(
	idPkB64u, pkReqB64u string,
	ctx Context,
	requestTs int64,
	ttlSecs uint32,
	nonceB64u, sigB64u string,
) error {
	idPk, err := base64.RawURLEncoding.DecodeString(idPkB64u)
	if err != nil || len(idPk) != ed25519.PublicKeySize {
		return errors.New("invalid id_pk")
	}
	pkReq, err := base64.RawURLEncoding.DecodeString(pkReqB64u)
	if err != nil || len(pkReq) != 32 {
		return errors.New("invalid pk_req")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(nonceB64u)
	if err != nil || len(nonce) != 16 {
		return errors.New("invalid request_nonce")
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64u)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("invalid sig")
	}

	contextHash := ComputeContextHash(ctx)
	signInput, err := BuildSignInput(idPk, pkReq, contextHash[:], requestTs, ttlSecs, nonce)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(idPk), signInput, sig) {
		return errors.New("signature verification failed")
	}
	return nil
}

// ComputeFingerprint returns the 8-char Base32 fingerprint (XXXX-XXXX) of a 32-byte Ed25519 public key.
func ComputeFingerprint(idPk []byte) (string, error) {
	if len(idPk) != ed25519.PublicKeySize {
		return "", fmt.Errorf("id_pk must be %d bytes", ed25519.PublicKeySize)
	}
	h := sha256.New()
	h.Write([]byte(fingerprintDomain))
	h.Write(idPk)
	sum := h.Sum(nil)
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:5])
	return encoded[:4] + "-" + encoded[4:8], nil
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
