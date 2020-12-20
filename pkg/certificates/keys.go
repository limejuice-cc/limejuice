// Copyright 2020 Limejuice-cc Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certificates

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	specs "github.com/limejuice-cc/api/go-api/crypto/v1alpha"
)

type baseKey struct {
	algorithm  specs.KeyAlgorithm
	size       int
	encoded    []byte
	privateKey crypto.PrivateKey
}

func (k *baseKey) Algorithm() specs.KeyAlgorithm {
	return k.algorithm
}

func (k *baseKey) Size() int {
	return k.size
}

func (k *baseKey) Encoded() []byte {
	return k.encoded
}

func (k *baseKey) PrivateKey() crypto.PrivateKey {
	return k.privateKey
}

func (k *baseKey) PublicKey() crypto.PublicKey {
	switch pub := k.privateKey.(type) {
	case *ecdsa.PrivateKey:
		return pub.Public()
	case *rsa.PrivateKey:
		return pub.Public()
	default:
		return nil
	}
}

// GenerateKey generates a new key from a key request
func GenerateKey(request *specs.CertificateKeyRequest) (specs.Key, error) {
	if err := request.Algorithm.ValidKeySize(request.Size); err != nil {
		return nil, err
	}
	switch request.Algorithm {
	case specs.ECDSAKey:
		return generateECDSAKey(request.Size)
	case specs.RSAKey:
		return generateRSAKey(request.Size)
	default:
		return nil, fmt.Errorf("unsupported key algorithm %s", request.Algorithm)
	}
}

type ecdsaKey struct {
	baseKey
}

func (k *ecdsaKey) SignatureAlgorithm() x509.SignatureAlgorithm {
	switch k.size {
	case 256:
		return x509.ECDSAWithSHA256
	case 384:
		return x509.ECDSAWithSHA384
	case 521:
		return x509.ECDSAWithSHA512
	default:
		return 0
	}
}

func (k *ecdsaKey) PublicKeyAlgorithm() x509.PublicKeyAlgorithm {
	return x509.ECDSA
}

func generateECDSAKey(size int) (*ecdsaKey, error) {
	if size == 0 {
		size = specs.ECDSAKey.DefaultSize()
	}
	var curve elliptic.Curve
	switch size {
	case 256:
		curve = elliptic.P256()
	case 384:
		curve = elliptic.P384()
	case 521:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("invalid key size %d", size)
	}

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	encoded, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	out := &ecdsaKey{}
	out.algorithm = specs.ECDSAKey
	out.size = size
	out.encoded = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded})
	out.privateKey = key

	return out, nil
}

type rsaKey struct {
	baseKey
}

func (k *rsaKey) PublicKeyAlgorithm() x509.PublicKeyAlgorithm {
	return x509.RSA
}

func (k *rsaKey) SignatureAlgorithm() x509.SignatureAlgorithm {
	switch {
	case k.size >= 4096:
		return x509.SHA512WithRSA
	case k.size >= 3072:
		return x509.SHA384WithRSA
	case k.size >= 2048:
		return x509.SHA256WithRSA
	default:
		return 0
	}
}

func generateRSAKey(size int) (*rsaKey, error) {
	if size == 0 {
		size = specs.RSAKey.DefaultSize()
	}

	key, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil, err
	}

	encoded := x509.MarshalPKCS1PrivateKey(key)
	if err != nil {
		return nil, err
	}

	out := &rsaKey{}
	out.algorithm = specs.RSAKey
	out.size = size
	out.encoded = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: encoded})
	out.privateKey = key

	return out, nil
}

func getCurveSize(c elliptic.Curve) int {
	if c == elliptic.P256() {
		return 256
	}
	if c == elliptic.P384() {
		return 384
	}
	if c == elliptic.P521() {
		return 521
	}
	return specs.ECDSAKey.DefaultSize()
}

func parsePrivateKey(keyPEM []byte) (specs.Key, error) {
	p, _ := pem.Decode(keyPEM)
	keyDER := p.Bytes

	if rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(keyDER); err == nil {
		out := &rsaKey{}
		out.algorithm = specs.RSAKey
		out.size = rsaPrivateKey.Size()
		out.encoded = keyPEM
		out.privateKey = rsaPrivateKey
		return out, nil
	}

	if edcsaPrivateKey, err := x509.ParseECPrivateKey(keyDER); err == nil {
		out := &ecdsaKey{}
		out.algorithm = specs.ECDSAKey
		out.size = getCurveSize(edcsaPrivateKey.Curve)
		out.encoded = keyPEM
		out.privateKey = edcsaPrivateKey
		return out, nil
	}

	return nil, errors.New("unknown private key type")
}
