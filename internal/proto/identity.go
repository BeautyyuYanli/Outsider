package proto

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
	requestDomain     = "outsider-req-v1"
	fingerprintDomain = "outsider-id-fp-v1"
)

// IdentityKey holds a client's long-lived Ed25519 signing identity.
type IdentityKey struct {
	priv ed25519.PrivateKey
}

// GenerateIdentityKey creates a fresh random Ed25519 identity key.
func GenerateIdentityKey() (*IdentityKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate Ed25519 key: %w", err)
	}
	return &IdentityKey{priv: priv}, nil
}

// IdentityKeyFromSeed constructs an IdentityKey from a 32-byte Ed25519 seed.
func IdentityKeyFromSeed(seed []byte) (*IdentityKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("identity key must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &IdentityKey{priv: priv}, nil
}

// IdentityKeyFromB64u decodes a Base64URL (no padding) 32-byte Ed25519 seed.
func IdentityKeyFromB64u(encoded string) (*IdentityKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("invalid identity key encoding: %w", err)
	}
	defer clear(raw)
	return IdentityKeyFromSeed(raw)
}

// SeedB64u returns the 32-byte seed encoded as Base64URL (no padding) in a wipeable byte slice.
func (k *IdentityKey) SeedB64u() []byte {
	seed := k.priv.Seed()
	defer clear(seed)
	out := make([]byte, base64.RawURLEncoding.EncodedLen(len(seed)))
	base64.RawURLEncoding.Encode(out, seed)
	return out
}

// Wipe zeros the private key bytes in memory.
func (k *IdentityKey) Wipe() {
	if k != nil && k.priv != nil {
		clear(k.priv)
	}
}

// PublicKeyBytes returns a copy of the 32-byte Ed25519 public key.
func (k *IdentityKey) PublicKeyBytes() []byte {
	pub := k.priv.Public().(ed25519.PublicKey)
	out := make([]byte, ed25519.PublicKeySize)
	copy(out, pub)
	return out
}

// PublicKeyB64u returns the Base64URL (no padding) encoded public key.
func (k *IdentityKey) PublicKeyB64u() string {
	return base64.RawURLEncoding.EncodeToString(k.PublicKeyBytes())
}

// Fingerprint returns the 8-char Base32 fingerprint (XXXX-XXXX).
func (k *IdentityKey) Fingerprint() string {
	fp, _ := ComputeFingerprint(k.PublicKeyBytes())
	return fp
}

// SignRequest signs the canonical 140-byte request signing payload.
func (k *IdentityKey) SignRequest(pkReq, contextHash []byte, requestTs int64, ttlSecs uint32, nonce []byte) ([]byte, error) {
	input, err := BuildSignInput(k.PublicKeyBytes(), pkReq, contextHash, requestTs, ttlSecs, nonce)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(k.priv, input), nil
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
