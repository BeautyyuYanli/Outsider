package sopsage

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

const (
	defaultIVSize = 32
	dataKeySize   = 32
	sopsVersion   = "3.9.0"
)

var (
	// ErrInvalidFormat indicates malformed SOPS YAML or metadata (exit 100).
	ErrInvalidFormat = errors.New("invalid sops file format")
	// ErrKeyNotFound indicates a requested key path does not exist (exit 100).
	ErrKeyNotFound = errors.New("sops key not found")
	// ErrDecrypt indicates age key decryption, AEAD decryption, or MAC verification failure (exit 103).
	ErrDecrypt = errors.New("sops decryption failed")
)

var encValuePattern = regexp.MustCompile(
	`^ENC\[AES256_GCM,data:([^,]*),iv:([^,]+),tag:([^,]+),type:([^,\]]+)\]$`,
)

// ParseAgeIdentity extracts and parses an age X25519 secret identity from raw bytes.
// Compatible with single-line AGE-SECRET-KEY-1... or multi-line age-keygen output.
func ParseAgeIdentity(raw []byte) (*age.X25519Identity, error) {
	text := string(raw)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "AGE-SECRET-KEY-1") {
			id, err := age.ParseX25519Identity(line)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid age secret key: %v", ErrDecrypt, err)
			}
			return id, nil
		}
	}
	return nil, fmt.Errorf("%w: no AGE-SECRET-KEY-1 line found in provided secret", ErrDecrypt)
}

// ValidateRecipient checks that s is a valid age1... X25519 public key.
func ValidateRecipient(s string) error {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "age1") {
		return fmt.Errorf("invalid age recipient %q: must start with age1", s)
	}
	if _, err := age.ParseX25519Recipient(s); err != nil {
		return fmt.Errorf("invalid age recipient %q: %w", s, err)
	}
	return nil
}

// encryptDataKeyAge wraps a 32-byte SOPS Data Key for an age1... recipient in ASCII armor.
func encryptDataKeyAge(dataKey []byte, recipientStr string) (string, error) {
	rec, err := age.ParseX25519Recipient(strings.TrimSpace(recipientStr))
	if err != nil {
		return "", fmt.Errorf("parse age recipient %q: %w", recipientStr, err)
	}
	var buf bytes.Buffer
	armored := armor.NewWriter(&buf)
	w, err := age.Encrypt(armored, rec)
	if err != nil {
		return "", fmt.Errorf("age encrypt init: %w", err)
	}
	if _, err := w.Write(dataKey); err != nil {
		return "", fmt.Errorf("age encrypt write: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("age encrypt close: %w", err)
	}
	if err := armored.Close(); err != nil {
		return "", fmt.Errorf("age armor close: %w", err)
	}
	return buf.String(), nil
}

// decryptDataKeyAge tries all sops.age entries until one decrypts a 32-byte Data Key.
func decryptDataKeyAge(entries []ageKeyEntry, identity *age.X25519Identity) ([]byte, error) {
	var lastErr error
	for _, e := range entries {
		if strings.TrimSpace(e.Enc) == "" {
			continue
		}
		armored := armor.NewReader(strings.NewReader(e.Enc))
		r, err := age.Decrypt(armored, identity)
		if err != nil {
			lastErr = err
			continue
		}
		key, err := io.ReadAll(r)
		if err != nil {
			lastErr = err
			continue
		}
		if len(key) != dataKeySize {
			clear(key)
			lastErr = fmt.Errorf("unexpected data key length %d", len(key))
			continue
		}
		return key, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("%w: failed to decrypt SOPS data key with provided age key: %v", ErrDecrypt, lastErr)
	}
	return nil, fmt.Errorf("%w: no age key entries found in sops metadata", ErrDecrypt)
}

func encryptAESGCM(plaintext []byte, dataKey []byte, aad []byte, valueType string) (string, error) {
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return "", fmt.Errorf("init AES cipher: %w", err)
	}
	iv := make([]byte, defaultIVSize)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("generate IV: %w", err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return "", fmt.Errorf("init AES-GCM: %w", err)
	}
	sealed := gcm.Seal(nil, iv, plaintext, aad)
	tagSize := gcm.Overhead()
	ct := sealed[:len(sealed)-tagSize]
	tag := sealed[len(sealed)-tagSize:]

	return fmt.Sprintf(
		"ENC[AES256_GCM,data:%s,iv:%s,tag:%s,type:%s]",
		base64.StdEncoding.EncodeToString(ct),
		base64.StdEncoding.EncodeToString(iv),
		base64.StdEncoding.EncodeToString(tag),
		valueType,
	), nil
}

func isEncryptedString(s string) bool {
	return encValuePattern.MatchString(s)
}

func decryptAESGCM(encStr string, dataKey []byte, aad []byte) ([]byte, string, error) {
	m := encValuePattern.FindStringSubmatch(encStr)
	if m == nil {
		return nil, "", fmt.Errorf("%w: malformed ENC[...] token", ErrDecrypt)
	}
	dataBytes, err := base64.StdEncoding.DecodeString(m[1])
	if err != nil {
		return nil, "", fmt.Errorf("%w: decode data: %v", ErrDecrypt, err)
	}
	ivBytes, err := base64.StdEncoding.DecodeString(m[2])
	if err != nil {
		return nil, "", fmt.Errorf("%w: decode iv: %v", ErrDecrypt, err)
	}
	tagBytes, err := base64.StdEncoding.DecodeString(m[3])
	if err != nil {
		return nil, "", fmt.Errorf("%w: decode tag: %v", ErrDecrypt, err)
	}
	valType := m[4]

	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, "", fmt.Errorf("%w: init AES cipher: %v", ErrDecrypt, err)
	}
	if len(ivBytes) == 0 {
		return nil, "", fmt.Errorf("%w: empty IV", ErrDecrypt)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(ivBytes))
	if err != nil {
		return nil, "", fmt.Errorf("%w: init AES-GCM (iv=%d): %v", ErrDecrypt, len(ivBytes), err)
	}
	combined := make([]byte, len(dataBytes)+len(tagBytes))
	copy(combined, dataBytes)
	copy(combined[len(dataBytes):], tagBytes)

	plain, err := gcm.Open(nil, ivBytes, combined, aad)
	if err != nil {
		return nil, "", fmt.Errorf("%w: AES-GCM authentication failed", ErrDecrypt)
	}
	return plain, valType, nil
}

// sopsMACBytes converts a decrypted or plaintext scalar value to the exact byte sequence hashed by official SOPS.
// Note: official SOPS formats bools as capitalized "True"/"False" (matching Python SOPS) in MAC calculation.
func sopsMACBytes(raw []byte, valType string) ([]byte, error) {
	switch valType {
	case "str", "bytes":
		return raw, nil
	case "int":
		n, err := strconv.ParseInt(string(raw), 10, 64)
		if err != nil {
			return raw, nil
		}
		return []byte(strconv.FormatInt(n, 10)), nil
	case "float":
		f, err := strconv.ParseFloat(string(raw), 64)
		if err != nil {
			return raw, nil
		}
		return []byte(strconv.FormatFloat(f, 'f', -1, 64)), nil
	case "bool":
		b, err := strconv.ParseBool(string(raw))
		if err != nil {
			return raw, nil
		}
		if b {
			return []byte("True"), nil
		}
		return []byte("False"), nil
	default:
		return raw, nil
	}
}

// normalizeExposedValue converts SOPS-internal scalar encodings (like bool "True"/"False") to standard lowercase for env/file handoff.
func normalizeExposedValue(raw []byte, valType string) []byte {
	if valType == "bool" {
		if b, err := strconv.ParseBool(string(raw)); err == nil {
			return []byte(strconv.FormatBool(b))
		}
	}
	return raw
}

func computeSHA512Hex(chunks [][]byte) string {
	h := sha512.New()
	for _, c := range chunks {
		h.Write(c)
	}
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}
