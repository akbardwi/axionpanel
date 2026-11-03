// Package secret encrypts values stored in `_enc` columns, following
// docs/spec.md §5.4: AES-256-GCM, encoded as "v1:" + base64(nonce||ciphertext),
// keyed by a 32-byte secret.key file readable only by the panel user.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

const (
	keySize = 32
	prefix  = "v1:"
)

// ErrDecrypt hides the failure reason so callers cannot be used as an oracle.
var ErrDecrypt = errors.New("secret: cannot decrypt value")

// Box seals and opens values with one key.
type Box struct {
	aead cipher.AEAD
}

// stat is a seam for tests checking file permissions.
var stat = os.Stat

// LoadOrCreate reads the key at path, creating a new random key with mode
// 0600 if the file does not exist. An existing file with the wrong size is an
// error: silently replacing it would orphan every encrypted value.
func LoadOrCreate(path string) (*Box, error) {
	key, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		key = make([]byte, keySize)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("secret: generate key: %w", err)
		}
		// O_EXCL: never clobber a key created concurrently.
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, fmt.Errorf("secret: create key: %w", err)
		}
		if _, err := f.Write(key); err != nil {
			f.Close()
			return nil, fmt.Errorf("secret: write key: %w", err)
		}
		if err := f.Close(); err != nil {
			return nil, fmt.Errorf("secret: write key: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("secret: read key: %w", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("secret: stat key: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("secret: key must be a regular owner-only file (chmod 600)")
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("secret: %s holds %d bytes, want %d", path, len(key), keySize)
	}
	return newBox(key)
}

func newBox(key []byte) (*Box, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Seal encrypts plaintext with a fresh random nonce.
func (b *Box) Seal(plaintext string) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("secret: nonce: %w", err)
	}
	sealed := b.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return prefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// Open decrypts a value produced by Seal.
func (b *Box) Open(encoded string) (string, error) {
	body, ok := strings.CutPrefix(encoded, prefix)
	if !ok {
		return "", ErrDecrypt
	}
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil || len(raw) < b.aead.NonceSize() {
		return "", ErrDecrypt
	}
	nonce, ct := raw[:b.aead.NonceSize()], raw[b.aead.NonceSize():]
	plain, err := b.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", ErrDecrypt
	}
	return string(plain), nil
}
