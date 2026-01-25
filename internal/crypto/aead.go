package crypto

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KeySize   = chacha20poly1305.KeySize
	NonceSize = chacha20poly1305.NonceSize
)

func Encrypt(key, plaintext []byte) (nonce, ciphertext []byte, err error) {
	if len(key) != KeySize {
		return nil, nil, errors.New("crypto: invalid key size")
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}

	ciphertext = aead.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

func Decrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, errors.New("crypto: invalid key size")
	}
	if len(nonce) != NonceSize {
		return nil, errors.New("crypto: invalid nonce size")
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("crypto: decryption failed (authentication error)")
	}

	return plaintext, nil
}

func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}
