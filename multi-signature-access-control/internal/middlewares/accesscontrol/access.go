package accesscontrol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
)

type KeyPair struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  ecdsa.PublicKey
}

// GenerateKey generates a new  key pair.
func GenerateKey() (*KeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  privateKey.PublicKey,
	}, nil
}

// Sign signs a message using -like ECDSA.
func Sign(msg string, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256([]byte(msg))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, err
	}
	return append(r.Bytes(), s.Bytes()...), nil
}

// Verify verifies a  signature.
func Verify(msg string, sig []byte, pubKey ecdsa.PublicKey) bool {
	if len(sig) != 64 {
		return false
	}
	hash := sha256.Sum256([]byte(msg))
	r := sig[:32]
	s := sig[32:]
	return ecdsa.Verify(&pubKey, hash[:], new(big.Int).SetBytes(r), new(big.Int).SetBytes(s))
}

// StringToPrivateKey converts a hex-encoded private key string to *ecdsa.PrivateKey.
func StringToPrivateKey(hexKey string) (*ecdsa.PrivateKey, error) {
	bytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, errors.New("invalid hex encoding")
	}

	privKey := new(big.Int).SetBytes(bytes)
	curve := elliptic.P256()

	if privKey.Cmp(curve.Params().N) >= 0 {
		return nil, errors.New("private key is out of range")
	}

	privateKey := new(ecdsa.PrivateKey)
	privateKey.D = privKey
	privateKey.PublicKey.Curve = curve
	privateKey.PublicKey.X, privateKey.PublicKey.Y = curve.ScalarBaseMult(bytes)

	return privateKey, nil
}

// StringToPublicKey converts a hex-encoded public key string to ecdsa.PublicKey.
func StringToPublicKey(hexKey string) (*ecdsa.PublicKey, error) {
	bytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, errors.New("invalid hex encoding")
	}

	if len(bytes) != 64 {
		return nil, errors.New("invalid public key length")
	}

	curve := elliptic.P256()
	x := new(big.Int).SetBytes(bytes[:32])
	y := new(big.Int).SetBytes(bytes[32:])

	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("invalid public key: point is not on curve")
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// PublicKeyToString converts an ecdsa.PublicKey to a hex-encoded string.
func PublicKeyToString(pubKey ecdsa.PublicKey) string {
	xBytes := pubKey.X.Bytes()
	yBytes := pubKey.Y.Bytes()
	return hex.EncodeToString(append(xBytes, yBytes...))
}

// PrivateKeyToString converts an ecdsa.PrivateKey to a hex-encoded string
func PrivateKeyToString(privKey *ecdsa.PrivateKey) string {
	dBytes := privKey.D.Bytes()
	return hex.EncodeToString(dBytes)
}

// PrivateKeyToBytes converts an ecdsa.PrivateKey to a byte array
func PrivateKeyToBytes(privKey *ecdsa.PrivateKey) []byte {
	return privKey.D.Bytes()
}
