// Copyright © 2015 Nik Unger
//
// This file is part of ringsig.
//
// Ringsig is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// Ringsig is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
// details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with ringsig. If not, see <http://www.gnu.org/licenses/>.

package ringsig_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	mrand "math/rand"
	"strings"
	"testing"

	"github.com/Nik-U/ringsig"
)

type randPRNG mrand.Rand

func (prng *randPRNG) Read(p []byte) (n int, err error) {
	n = len(p)
	err = nil

	// We pull 7 bytes out of every random int64 (MSB is always 0)
	r := (*mrand.Rand)(prng)
	var x int64
	for i := 0; i < n; i++ {
		if i%7 == 0 {
			x = r.Int63()
		}
		p[i] = byte(x & 0xFF)
		x >>= 8
	}
	return
}

func newRandPRNG(seed int64) io.Reader { return (*randPRNG)(mrand.New(mrand.NewSource(seed))) }

func getReplaceBytes(buf *bytes.Buffer) []byte {
	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	buf.Reset()
	buf.Write(result)
	return result
}

func testExportable(t *testing.T, name string, data ringsig.Exportable, importer func(io.Reader) (ringsig.Exportable, error)) {
	buf := new(bytes.Buffer)

	var err error
	var n int64

	if n, err = data.WriteTo(buf); err != nil {
		t.Errorf("failed to export %s: %v", name, err)
		return
	}
	dataBytes := getReplaceBytes(buf)
	if n != int64(len(dataBytes)) {
		t.Errorf("export size mismatch: reported %d, got %d", n, len(dataBytes))
	}
	data2, err := importer(buf)
	if err != nil {
		t.Errorf("failed to import %s: %v", name, err)
		return
	}
	buf.Reset()
	data2.WriteTo(buf)
	if !bytes.Equal(buf.Bytes(), dataBytes) {
		t.Errorf("loading %s produced different export", name)
	}
	if !bytes.Equal(data2.Bytes(), dataBytes) {
		t.Errorf("%s returned different bytes than it wrote", name)
	}
}

func testSigning(t *testing.T, name string, sign bool, verify bool, scheme ringsig.Scheme, messages []string, signRing []ringsig.PublicKey, verifyRing []ringsig.PublicKey, keyPair *ringsig.KeyPair) {
	if verifyRing == nil {
		verifyRing = signRing
	}
	for i, message := range messages {
		if sig, err := scheme.Sign(message, signRing, keyPair); (sign && (err != nil || sig == nil)) || (!sign && (err == nil || sig != nil)) {
			t.Errorf("signing \"%s\" on msg %d: have err \"%v\", sig %t, but expected success %t", name, i, err, (sig != nil), sign)
		} else {
			if scheme.Verify(message, sig, verifyRing) != verify {
				t.Errorf("verifying \"%s\" on msg %d: have %t, want %t", name, i, !verify, verify)
			}
		}
	}
}

func testScheme(t *testing.T, canCheckKeys bool, newScheme func() (ringsig.Scheme, error), loadScheme func(params io.Reader) (ringsig.Scheme, error)) {
	// Generate new parameters
	scheme, err := newScheme()
	if err != nil {
		t.Fatalf("failed to generate scheme: %v", err)
	}

	// Generate a key pair
	firstPair := scheme.KeyGen()
	if firstPair == nil {
		t.Fatal("failed to generate a key pair")
	}

	// Recreate scheme from exported data; it should be the same
	testExportable(t, "scheme", scheme, func(r io.Reader) (ringsig.Exportable, error) {
		var err error
		scheme, err = loadScheme(r)
		return scheme, err
	})
	if scheme == nil {
		t.Fatal("cannot continue")
	}

	// Test imports / exports of keys
	{
		key := scheme.KeyGen()
		testExportable(t, "key", key, func(r io.Reader) (ringsig.Exportable, error) { return scheme.LoadKeyPair(r) })
		testExportable(t, "public key", key.Public, func(r io.Reader) (ringsig.Exportable, error) { return scheme.LoadPublicKey(r) })
		testExportable(t, "private key", key.Private, func(r io.Reader) (ringsig.Exportable, error) { return scheme.LoadPrivateKey(r) })
	}

	// Import the key created earlier. If it is incompatible, we'll fail later
	keypairs := []*ringsig.KeyPair{}
	buf := &bytes.Buffer{}
	if _, err := firstPair.WriteTo(buf); err != nil {
		t.Fatalf("could not export first keypair: %v", err)
	}
	if restoredPair, err := scheme.LoadKeyPair(buf); err != nil {
		t.Fatalf("could not import first keypair: %v", err)
	} else {
		keypairs = append(keypairs, restoredPair)
	}

	// Generate additional keys for the universe
	for i := 1; i < 5; i++ {
		keypairs = append(keypairs, scheme.KeyGen())
	}
	ring := make([]ringsig.PublicKey, len(keypairs))
	for i, pair := range keypairs {
		ring[i] = pair.Public
	}

	// Check key equality
	if keypairs[1].Public.Equals(keypairs[2].Public) {
		t.Errorf("keypair1 vs keypair2: have equal, want not equal")
	}
	if !keypairs[3].Public.Equals(keypairs[3].Public) {
		t.Errorf("keypair3 vs keypair3: have not equal, want equal")
	}

	// Testing messages
	messages := []string{"message", "Hello, World!", "Hello, 世界", string([]byte{0, 1, 2, 10, 13, 254, 255}), "", strings.Repeat("!", 1024*128)}
	quickMessages := []string{"For other tests, one simple message. ☺"}

	// Test signatures
	testSigning(t, "ring size 2", true, true, scheme, messages, ring[1:3], nil, keypairs[1])
	testSigning(t, "post-import ring", true, true, scheme, quickMessages, ring[1:], nil, keypairs[2])
	testSigning(t, "full ring", true, true, scheme, quickMessages, ring, nil, keypairs[0])

	// Some tests requiring a valid signature
	if sig, err := scheme.Sign(quickMessages[0], ring, keypairs[0]); err != nil || sig == nil {
		t.Errorf("failed to generate simple signature: %v", err)
	} else {
		// Test signature import / export
		testExportable(t, "signature", sig, func(r io.Reader) (ringsig.Exportable, error) { return scheme.LoadSignature(r) })

		// Test many random 1-bit corruptions; none should verify
		buf.Reset()
		if _, err = sig.WriteTo(buf); err != nil {
			t.Errorf("failed to export signature for corruption test: %v", err)
		} else {
			sigBytes := getReplaceBytes(buf)
			for i := 0; i < 100; i++ {
				// Flip one bit at random
				flipPos := mrand.Intn(len(sigBytes))
				sigBytes[flipPos] ^= 0x10

				// The signature should fail to be imported, or fail to verify
				sig, err = scheme.LoadSignature(bytes.NewReader(sigBytes))
				if err != nil {
					if scheme.Verify(quickMessages[0], sig, ring) {
						t.Errorf("corrupted signature byte %d: have verified, want unverified", flipPos)
					}
				}

				// Unflip
				sigBytes[flipPos] ^= 0x10
			}
		}
	}

	// Test various failure conditions
	{
		if canCheckKeys {
			key := scheme.KeyGen()
			testSigning(t, "with wrong secret", false, false, scheme, quickMessages, ring, nil, key)
		}
		for i := 1; i >= 0; i-- {
			testSigning(t, fmt.Sprintf("ring size %d", i), false, false, scheme, quickMessages, ring[0:i], nil, keypairs[0])
		}
		testSigning(t, "subring mismatch high", true, false, scheme, quickMessages, ring, ring[0:len(ring)-1], keypairs[0])
		testSigning(t, "subring mismatch low", true, false, scheme, quickMessages, ring, ring[1:], keypairs[0])
		testSigning(t, "superring mismatch", true, false, scheme, quickMessages, ring[0:2], ring, keypairs[0])
		testSigning(t, "ring duplication", false, false, scheme, quickMessages, []ringsig.PublicKey{ring[0], ring[1], ring[0]}, nil, keypairs[0])
	}

	// Test corrupted load
	buf.Reset()
	if _, err := scheme.WriteTo(buf); err != nil {
		t.Errorf("failed to export bytes for corruption test")
	} else {
		data := buf.Bytes()
		if _, err := rand.Read(data); err != nil {
			t.Errorf("failed to load entropy for corruption test")
		} else {
			buf.Write(data)
			scheme2, err := loadScheme(buf)
			if scheme2 != nil || err == nil {
				t.Errorf("importing corrupted data: have %p, want error", scheme2)
			}
		}
	}
}

func TestShacham1(t *testing.T) {
	testScheme(t, true, func() (ringsig.Scheme, error) { return ringsig.NewShacham(1) }, ringsig.LoadShacham)
}

func TestShacham2(t *testing.T) {
	testScheme(t, true, func() (ringsig.Scheme, error) { return ringsig.NewShacham(2) }, ringsig.LoadShacham)
}

func TestShacham3(t *testing.T) {
	testScheme(t, true, func() (ringsig.Scheme, error) { return ringsig.NewShacham(3) }, ringsig.LoadShacham)
}

func benchmarkKeyGen(b *testing.B, scheme ringsig.Scheme) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scheme.KeyGen()
	}
}

func benchmarkSign(b *testing.B, scheme ringsig.Scheme) {
	alice := scheme.KeyGen()
	bob := scheme.KeyGen()
	ring := []ringsig.PublicKey{alice.Public, bob.Public}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scheme.Sign("sign", ring, alice)
	}
}

func benchmarkVerify(b *testing.B, scheme ringsig.Scheme) {
	alice := scheme.KeyGen()
	bob := scheme.KeyGen()
	ring := []ringsig.PublicKey{alice.Public, bob.Public}

	message := "verify"
	sig, err := scheme.Sign(message, ring, alice)
	if err != nil {
		b.Fatalf("failed to sign message: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scheme.Verify(message, sig, ring)
	}
}

func newShachamOrPanic(securityFactor uint8) ringsig.Scheme {
	scheme, err := ringsig.NewShacham(securityFactor)
	if err != nil {
		panic(err)
	}
	return scheme
}

func BenchmarkShacham1KeyGen(b *testing.B) { benchmarkKeyGen(b, newShachamOrPanic(1)) }
func BenchmarkShacham2KeyGen(b *testing.B) { benchmarkKeyGen(b, newShachamOrPanic(2)) }
func BenchmarkShacham3KeyGen(b *testing.B) { benchmarkKeyGen(b, newShachamOrPanic(3)) }
func BenchmarkShacham1Sign(b *testing.B)   { benchmarkSign(b, newShachamOrPanic(1)) }
func BenchmarkShacham2Sign(b *testing.B)   { benchmarkSign(b, newShachamOrPanic(2)) }
func BenchmarkShacham3Sign(b *testing.B)   { benchmarkSign(b, newShachamOrPanic(3)) }
func BenchmarkShacham1Verify(b *testing.B) { benchmarkVerify(b, newShachamOrPanic(1)) }
func BenchmarkShacham2Verify(b *testing.B) { benchmarkVerify(b, newShachamOrPanic(2)) }
func BenchmarkShacham3Verify(b *testing.B) { benchmarkVerify(b, newShachamOrPanic(3)) }
