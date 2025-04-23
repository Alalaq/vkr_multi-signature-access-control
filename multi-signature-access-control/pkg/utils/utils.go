package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

var encryptionKey = []byte("multi-signature-access-controlCK")

func NewPointer[T comparable](value T) *T {
	return &value
}

func GetPointerValue[T comparable](ptr *T) T {
	if ptr == nil {
		var val T
		return val
	}
	return *ptr
}

func GetValueOrDefault[T comparable](ptr *T, defaultVal T) T {
	if ptr != nil {
		return *ptr
	}
	return defaultVal
}

func EncryptSecret(secret string) (string, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(secret))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(secret))

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DecryptSecret(encryptedSecret string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedSecret)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

// CheckSecretHash now checks if the decrypted secret matches the provided secret.
func CheckSecretHash(secret, encryptedSecret string) bool {
	decrypted, err := DecryptSecret(encryptedSecret)
	if err != nil {
		return false
	}
	return decrypted == secret
}
