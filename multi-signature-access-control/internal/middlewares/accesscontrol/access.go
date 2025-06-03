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

// SchnorrSign signs a message using Schnorr signature scheme
func SchnorrSign(msg string, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	// Step 1: Hash the message
	hash := sha256.Sum256([]byte(msg))

	// Step 2: Generate random nonce k
	k, err := rand.Int(rand.Reader, privateKey.Curve.Params().N)
	if err != nil {
		return nil, err
	}

	// Step 3: Compute R = k*G
	Rx, Ry := privateKey.Curve.ScalarBaseMult(k.Bytes())

	// Step 4: Compute e = H(Rx || Ry || msg)
	e := sha256.Sum256(append(append(Rx.Bytes(), Ry.Bytes()...), hash[:]...))
	eInt := new(big.Int).SetBytes(e[:])

	// Step 5: Compute s = k + e*d mod N
	s := new(big.Int).Mul(eInt, privateKey.D)
	s.Add(s, k)
	s.Mod(s, privateKey.Curve.Params().N)

	// Signature is (Rx, s)
	return append(Rx.Bytes(), s.Bytes()...), nil
}

// SchnorrVerify verifies a Schnorr signature
func SchnorrVerify(msg string, sig []byte, pubKey ecdsa.PublicKey) bool {
	if len(sig) != 64 {
		return false
	}

	hash := sha256.Sum256([]byte(msg))
	Rx := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])

	if Rx.Cmp(pubKey.Curve.Params().P) >= 0 {
		return false
	}

	Ry := new(big.Int)
	Ry.Exp(pubKey.Curve.Params().Gx, Rx, pubKey.Curve.Params().P)
	if Ry.Cmp(pubKey.Curve.Params().Gy) != 0 {
		return false
	}

	e := sha256.Sum256(append(Rx.Bytes(), hash[:]...))
	eInt := new(big.Int).SetBytes(e[:])

	sGx, sGy := pubKey.Curve.ScalarBaseMult(s.Bytes())
	ePx, ePy := pubKey.Curve.ScalarMult(pubKey.X, pubKey.Y, eInt.Bytes())

	ePyNeg := new(big.Int).Neg(ePy)
	ePyNeg.Mod(ePyNeg, pubKey.Curve.Params().P)

	RxPrime, _ := pubKey.Curve.Add(sGx, sGy, ePx, ePyNeg)

	return Rx.Cmp(RxPrime) == 0
}

// AggregateSchnorrSignatures combines multiple Schnorr signatures into one
func AggregateSchnorrSignatures(sigs [][]byte) ([]byte, error) {
	if len(sigs) == 0 {
		return nil, errors.New("no signatures to aggregate")
	}

	for _, sig := range sigs {
		if len(sig) != 64 {
			return nil, errors.New("invalid signature length")
		}
	}

	aggregatedS := new(big.Int)
	for _, sig := range sigs {
		s := new(big.Int).SetBytes(sig[32:])
		aggregatedS.Add(aggregatedS, s)
	}

	aggregatedRx := sigs[0][:32]

	return append(aggregatedRx, aggregatedS.Bytes()...), nil
}

// VerifyAggregatedSchnorr verifies an aggregated Schnorr signature
func VerifyAggregatedSchnorr(msg string, sig []byte, pubKeys []ecdsa.PublicKey) bool {
	if len(sig) != 64 || len(pubKeys) == 0 {
		return false
	}

	hash := sha256.Sum256([]byte(msg))
	Rx := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])

	aggregatedPx, aggregatedPy := pubKeys[0].X, pubKeys[0].Y
	for i := 1; i < len(pubKeys); i++ {
		aggregatedPx, aggregatedPy = pubKeys[i].Curve.Add(
			aggregatedPx, aggregatedPy,
			pubKeys[i].X, pubKeys[i].Y,
		)
	}

	e := sha256.Sum256(append(Rx.Bytes(), hash[:]...))
	eInt := new(big.Int).SetBytes(e[:])

	sGx, sGy := pubKeys[0].Curve.ScalarBaseMult(s.Bytes())
	ePx, ePy := pubKeys[0].Curve.ScalarMult(aggregatedPx, aggregatedPy, eInt.Bytes())

	ePyNeg := new(big.Int).Neg(ePy)
	ePyNeg.Mod(ePyNeg, pubKeys[0].Curve.Params().P)

	RxPrime, _ := pubKeys[0].Curve.Add(sGx, sGy, ePx, ePyNeg)

	return Rx.Cmp(RxPrime) == 0
}
