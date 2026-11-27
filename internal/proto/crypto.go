package proto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	hkdfInfoPrefix = "outsider-v1-aead-key"
	aadPrefix      = "outsider-v1"
)

// EphemeralKeypair is a single-use X25519 keypair generated per approval session.
type EphemeralKeypair struct {
	priv *ecdh.PrivateKey
	pub  []byte
}

// GenerateEphemeralKeypair generates a fresh random X25519 keypair.
func GenerateEphemeralKeypair() (*EphemeralKeypair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate X25519 keypair: %w", err)
	}
	return &EphemeralKeypair{
		priv: priv,
		pub:  priv.PublicKey().Bytes(),
	}, nil
}

// EphemeralKeypairFromBytes constructs an X25519 keypair from a 32-byte private key.
func EphemeralKeypairFromBytes(raw []byte) (*EphemeralKeypair, error) {
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse X25519 private key: %w", err)
	}
	return &EphemeralKeypair{
		priv: priv,
		pub:  priv.PublicKey().Bytes(),
	}, nil
}

// PublicBytes returns a copy of the 32-byte X25519 public key.
func (kp *EphemeralKeypair) PublicBytes() []byte {
	out := make([]byte, len(kp.pub))
	copy(out, kp.pub)
	return out
}

// PublicB64u returns the Base64URL (no padding) encoded public key.
func (kp *EphemeralKeypair) PublicB64u() string {
	return base64.RawURLEncoding.EncodeToString(kp.pub)
}

type plaintextPayload struct {
	V      int    `json:"v"`
	Secret string `json:"secret"`
}

// DecryptEnvelope decrypts an approved E2EE envelope and returns the raw secret bytes.
// Callers are responsible for clearing the returned slice with clear(secret).
func (kp *EphemeralKeypair) DecryptEnvelope(env Envelope, sessionID string, contextHash []byte) ([]byte, error) {
	if env.V != 1 {
		return nil, fmt.Errorf("unsupported envelope version: %d", env.V)
	}
	if len(contextHash) != 32 {
		return nil, fmt.Errorf("context_hash must be 32 bytes, got %d", len(contextHash))
	}

	epkBytes, err := base64.RawURLEncoding.DecodeString(env.EPK)
	if err != nil || len(epkBytes) != 32 {
		return nil, errors.New("invalid epk encoding or length")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(env.Nonce)
	if err != nil || len(nonce) != 12 {
		return nil, errors.New("invalid nonce encoding or length")
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(env.Ciphertext)
	if err != nil || len(ciphertext) < 16 {
		return nil, errors.New("invalid ciphertext encoding")
	}

	epk, err := ecdh.X25519().NewPublicKey(epkBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid epk public key: %w", err)
	}

	// crypto/ecdh rejects all-zero (non-contributory) X25519 shared secrets.
	shared, err := kp.priv.ECDH(epk)
	if err != nil {
		return nil, fmt.Errorf("X25519 ECDH failed: %w", err)
	}
	defer clear(shared)

	aeadKey, err := DeriveAEADKey(shared, sessionID, kp.pub, epkBytes)
	if err != nil {
		return nil, err
	}
	defer clear(aeadKey)

	block, err := aes.NewCipher(aeadKey)
	if err != nil {
		return nil, fmt.Errorf("init AES-256: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("init AES-256-GCM: %w", err)
	}

	aad := BuildAAD(sessionID, contextHash)
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("AEAD decryption or AAD authentication failed")
	}
	defer clear(plaintext)

	var parsed plaintextPayload
	if err := json.Unmarshal(plaintext, &parsed); err != nil {
		return nil, fmt.Errorf("invalid decrypted JSON payload: %w", err)
	}
	if parsed.V != 1 {
		return nil, fmt.Errorf("unsupported plaintext version: %d", parsed.V)
	}
	return []byte(parsed.Secret), nil
}

// EncryptEnvelope encrypts a secret for pkReq using X25519 + HKDF-SHA256 + AES-256-GCM.
// Primarily used in integration and vector tests.
func EncryptEnvelope(secret []byte, sessionID string, pkReq, contextHash []byte, epkPrivOverride, nonceOverride []byte) (Envelope, error) {
	if len(pkReq) != 32 {
		return Envelope{}, fmt.Errorf("pk_req must be 32 bytes, got %d", len(pkReq))
	}
	if len(contextHash) != 32 {
		return Envelope{}, fmt.Errorf("context_hash must be 32 bytes, got %d", len(contextHash))
	}

	var epkPriv *ecdh.PrivateKey
	var err error
	if len(epkPrivOverride) > 0 {
		epkPriv, err = ecdh.X25519().NewPrivateKey(epkPrivOverride)
	} else {
		epkPriv, err = ecdh.X25519().GenerateKey(rand.Reader)
	}
	if err != nil {
		return Envelope{}, fmt.Errorf("ephemeral key: %w", err)
	}
	epkBytes := epkPriv.PublicKey().Bytes()

	peerPub, err := ecdh.X25519().NewPublicKey(pkReq)
	if err != nil {
		return Envelope{}, fmt.Errorf("parse pk_req: %w", err)
	}
	shared, err := epkPriv.ECDH(peerPub)
	if err != nil {
		return Envelope{}, fmt.Errorf("X25519 ECDH: %w", err)
	}
	defer clear(shared)

	aeadKey, err := DeriveAEADKey(shared, sessionID, pkReq, epkBytes)
	if err != nil {
		return Envelope{}, err
	}
	defer clear(aeadKey)

	nonce := make([]byte, 12)
	if len(nonceOverride) > 0 {
		if len(nonceOverride) != 12 {
			return Envelope{}, fmt.Errorf("nonce must be 12 bytes, got %d", len(nonceOverride))
		}
		copy(nonce, nonceOverride)
	} else if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, err
	}

	plaintext, err := json.Marshal(plaintextPayload{V: 1, Secret: string(secret)})
	if err != nil {
		return Envelope{}, err
	}
	defer clear(plaintext)

	block, err := aes.NewCipher(aeadKey)
	if err != nil {
		return Envelope{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Envelope{}, err
	}

	aad := BuildAAD(sessionID, contextHash)
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	return Envelope{
		V:          1,
		EPK:        base64.RawURLEncoding.EncodeToString(epkBytes),
		Nonce:      base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
	}, nil
}

// DeriveAEADKey derives the 32-byte AES-256-GCM key via HKDF-SHA256.
func DeriveAEADKey(sharedSecret []byte, sessionID string, pkReq, epk []byte) ([]byte, error) {
	info := make([]byte, 0, len(hkdfInfoPrefix)+len(pkReq)+len(epk))
	info = append(info, hkdfInfoPrefix...)
	info = append(info, pkReq...)
	info = append(info, epk...)

	key, err := hkdf.Key(sha256.New, sharedSecret, []byte(sessionID), string(info), 32)
	if err != nil {
		return nil, fmt.Errorf("HKDF-SHA256 key derivation failed: %w", err)
	}
	return key, nil
}

// BuildAAD builds the AEAD Additional Authenticated Data binding session_id and context_hash.
func BuildAAD(sessionID string, contextHash []byte) []byte {
	aad := make([]byte, 0, len(aadPrefix)+1+len(sessionID)+1+len(contextHash))
	aad = append(aad, aadPrefix...)
	aad = append(aad, 0x00)
	aad = append(aad, sessionID...)
	aad = append(aad, 0x00)
	aad = append(aad, contextHash...)
	return aad
}
