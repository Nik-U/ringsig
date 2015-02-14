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

/*
	Package shacham implements efficient Shacham-Waters ring signatures. This
	scheme was published by Shacham and Waters in "Efficient Ring Signatures
	without Random Oracles". It provides full-key disclosure anonymity and
	insider corruption unforgeability while also being provably secure in the
	standard model. In this implementation, it relies on three complexity
	assumptions: integer factorization, computational Diffie-Hellman in prime
	order cyclic subgroups of elliptic curves, and subgroup decision in
	composite elliptic curves.
*/
package shacham

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"io"

	"github.com/Nik-U/pbc"
	"github.com/Nik-U/ringsig"
	"github.com/Nik-U/ringsig/internal/genutil"
	"github.com/Nik-U/ringsig/internal/rsutil"
)

type securityParams struct {
	rsaBits uint16
	H       hash.Hash
	k       int16
}

func shachamGetParams(securityFactor uint8) (*securityParams, error) {
	var s *securityParams
	switch securityFactor {
	case 1:
		s = &securityParams{rsaBits: 1024, H: sha256.New224()}
	case 2:
		s = &securityParams{rsaBits: 2048, H: sha512.New384()}
	case 3:
		s = &securityParams{rsaBits: 3072, H: sha512.New()}
	default:
		return nil, ringsig.ErrUnsupportedLevel
	}
	s.k = int16(s.H.Size()) * 8
	return s, nil
}

type scheme struct {
	// Shared parameters (from global setup)
	secFac uint8
	G      *pbc.Params
	g      *pbc.Element
	h      *pbc.Element
	u      []*pbc.Element // Element 0 is u'
	A      *pbc.Element
	B0     *pbc.Element
	Ahat   *pbc.Element

	// Runtime values
	secParams *securityParams
	pairing   *pbc.Pairing
	gPower    *pbc.Power
	hPower    *pbc.Power
	hPairer   *pbc.Pairer
	APairer   *pbc.Pairer
	AhatPower *pbc.Power
}

func (s *scheme) makeRuntime() {
	s.gPower = s.g.PreparePower()
	s.hPower = s.h.PreparePower()
	s.hPairer = s.h.PreparePairer()
	s.APairer = s.A.PreparePairer()
	s.AhatPower = s.Ahat.PreparePower()
}

// New creates a new Shacham-Waters ring signature scheme. Rings can be
// arbitrarily large. The scheme is secure in the standard model, with
// reasonable performance.
//
// Several levels of security are provided, based on the securityFactor
// parameter. Valid values are 1 to 3, inclusive, with 1 being the least secure,
// and 3 being the most secure. Level 1 is roughly equivalent to 80 bits of
// security, which is now widely considered to be weak. Levels 2 and 3 are
// roughly equivalent to 160 and 240 bits of security, respectively.
func New(securityFactor uint8) (ringsig.Scheme, error) {
	secParams, err := shachamGetParams(securityFactor)
	if err != nil {
		return nil, err
	}

	// Generate n=pq
	rsaKey, err := rsa.GenerateKey(rand.Reader, int(secParams.rsaBits))
	if err != nil {
		return nil, err
	}
	p := rsaKey.Primes[1]
	q := rsaKey.Primes[0]
	n := rsaKey.N

	// Construct the bilinear pairing of composite order
	params := pbc.GenerateA1(n)
	pairing := params.NewPairing()

	// Find generators
	g := pairing.NewG1().Rand().ThenPowBig(p)
	h := pairing.NewG1().Rand().ThenPowBig(q)
	u := make([]*pbc.Element, secParams.k+1)
	for i := int16(0); i <= secParams.k; i++ {
		u[i] = pairing.NewG1().Rand()
	}

	// Choose a, b0
	a := pairing.NewZr().Rand()
	b0 := pairing.NewZr().Rand()

	// Compute public values
	A := pairing.NewG1().PowZn(g, a)
	B0 := pairing.NewG1().PowZn(g, b0)
	Ahat := pairing.NewG1().PowZn(h, a)

	s := &scheme{
		secFac:    securityFactor,
		G:         params,
		g:         g,
		h:         h,
		u:         u,
		A:         A,
		B0:        B0,
		Ahat:      Ahat,
		secParams: secParams,
		pairing:   pairing,
	}
	s.makeRuntime()
	return s, nil
}

// Load restores a Shacham-Waters ring signature scheme from a Reader.
func Load(r io.Reader) (ringsig.Scheme, error) {
	gr := genutil.NewGobReader(r)
	var err error

	var securityFactor uint8
	gr.Decode(&securityFactor)
	secParams, err := shachamGetParams(securityFactor)
	if err != nil {
		return nil, err
	}

	var params *pbc.Params
	var paramStr string
	if !gr.Decode(&paramStr) || paramStr == "" {
		return nil, gr.Err()
	}
	if params, err = pbc.NewParamsFromString(paramStr); err != nil {
		return nil, err
	}
	pairing := params.NewPairing()

	s := &scheme{
		secFac:    securityFactor,
		G:         params,
		secParams: secParams,
		pairing:   pairing,

		g:    pairing.NewG1(),
		h:    pairing.NewG1(),
		A:    pairing.NewG1(),
		B0:   pairing.NewG1(),
		Ahat: pairing.NewG1(),
	}
	gr.DecodeElement(s.g)
	gr.DecodeElement(s.h)
	s.u = make([]*pbc.Element, secParams.k+1)
	for i := int16(0); i <= secParams.k; i++ {
		s.u[i] = pairing.NewG1()
		gr.DecodeElement(s.u[i])
	}
	gr.DecodeElement(s.A)
	gr.DecodeElement(s.B0)
	gr.DecodeElement(s.Ahat)
	if gr.Err() != nil {
		return nil, gr.Err()
	}
	s.makeRuntime()

	// Validate generation
	temp1 := pairing.NewGT().Pair(s.A, s.h)
	temp2 := pairing.NewGT().Pair(s.g, s.Ahat)
	if !temp1.Equals(temp2) {
		return nil, ringsig.ErrInvalidParameters
	}

	return s, nil
}

func (s *scheme) WriteTo(w io.Writer) (n int64, err error) {
	gw := genutil.NewGobWriter(w)
	gw.Encode(s.secFac)
	gw.Encode(s.G.String())
	gw.Encode(s.g.CompressedBytes())
	gw.Encode(s.h.CompressedBytes())
	for i := int16(0); i <= s.secParams.k; i++ {
		gw.Encode(s.u[i].CompressedBytes())
	}
	gw.Encode(s.A.CompressedBytes())
	gw.Encode(s.B0.CompressedBytes())
	gw.Encode(s.Ahat.CompressedBytes())
	return gw.Count(), gw.Err()
}

func (s *scheme) Bytes() []byte { return genutil.ConvertToBytes(s) }

type publicKey struct {
	g2b *pbc.Element
}

func (s *scheme) LoadPublicKey(r io.Reader) (ringsig.PublicKey, error) {
	pk := &publicKey{g2b: s.pairing.NewG1()}
	gr := genutil.NewGobReader(r)
	gr.DecodeElement(pk.g2b)
	if gr.Err() != nil {
		return nil, gr.Err()
	}
	return pk, nil
}

func (pk *publicKey) WriteTo(w io.Writer) (n int64, err error) {
	gw := genutil.NewGobWriter(w)
	gw.Encode(pk.g2b.CompressedBytes())
	return gw.Count(), gw.Err()
}

func (pk *publicKey) Bytes() []byte { return genutil.ConvertToBytes(pk) }

func (pk *publicKey) Equals(other ringsig.PublicKey) bool {
	if pk2, ok := other.(*publicKey); ok {
		return pk.g2b.Equals(pk2.g2b)
	}
	return false
}

type privateKey struct {
	A2b *pbc.Element
}

func (s *scheme) LoadPrivateKey(r io.Reader) (ringsig.PrivateKey, error) {
	sk := &privateKey{A2b: s.pairing.NewG1()}
	gr := genutil.NewGobReader(r)
	gr.DecodeElement(sk.A2b)
	if gr.Err() != nil {
		return nil, gr.Err()
	}
	return sk, nil
}

func (sk *privateKey) WriteTo(w io.Writer) (n int64, err error) {
	gw := genutil.NewGobWriter(w)
	gw.Encode(sk.A2b.CompressedBytes())
	return gw.Count(), gw.Err()
}

func (sk *privateKey) Bytes() []byte { return genutil.ConvertToBytes(sk) }

func (s *scheme) LoadKeyPair(r io.Reader) (*ringsig.KeyPair, error) {
	keypair, err := rsutil.LoadKeyPair(s, r)
	if err != nil {
		return nil, err
	}

	// Sanity check to ensure that the private key matches the public key
	pair1 := s.pairing.NewGT()
	pair2 := s.pairing.NewGT()
	pair1.Pair(s.A, keypair.Public.(*publicKey).g2b)
	pair2.Pair(s.g, keypair.Private.(*privateKey).A2b)
	if !pair1.Equals(pair2) {
		return nil, ringsig.ErrInvalidKeyPair
	}
	return keypair, nil
}

type signature struct {
	S1 *pbc.Element
	S2 *pbc.Element
	C  []*pbc.Element
	pi []*pbc.Element
}

func (s *scheme) LoadSignature(r io.Reader) (ringsig.Signature, error) {
	sig := &signature{
		S1: s.pairing.NewG1(),
		S2: s.pairing.NewG1(),
	}
	gr := genutil.NewGobReader(r)

	var ringSize uint32
	gr.Decode(&ringSize)
	sig.C = make([]*pbc.Element, ringSize)
	sig.pi = make([]*pbc.Element, ringSize)

	gr.DecodeElement(sig.S1)
	gr.DecodeElement(sig.S2)
	for i := uint32(0); i < ringSize; i++ {
		sig.C[i] = s.pairing.NewG1()
		sig.pi[i] = s.pairing.NewG1()
		gr.DecodeElement(sig.C[i])
		gr.DecodeElement(sig.pi[i])
	}
	if gr.Err() != nil {
		return nil, gr.Err()
	}
	return sig, nil
}

func (sig *signature) WriteTo(w io.Writer) (n int64, err error) {
	gw := genutil.NewGobWriter(w)

	ringSize := uint32(len(sig.C))
	gw.Encode(&ringSize)
	gw.Encode(sig.S1.CompressedBytes())
	gw.Encode(sig.S2.CompressedBytes())
	for i := uint32(0); i < ringSize; i++ {
		gw.Encode(sig.C[i].CompressedBytes())
		gw.Encode(sig.pi[i].CompressedBytes())
	}

	return gw.Count(), gw.Err()
}

func (sig *signature) Bytes() []byte { return genutil.ConvertToBytes(sig) }

func (s *scheme) KeyGen() *ringsig.KeyPair {
	b := s.pairing.NewZr().Rand()
	pk := s.pairing.NewG1().PowerZn(s.gPower, b)
	sk := s.pairing.NewG1().PowZn(s.A, b)
	return &ringsig.KeyPair{
		Public:  &publicKey{g2b: pk},
		Private: &privateKey{A2b: sk},
	}
}

func (s *scheme) checkRing(ring []ringsig.PublicKey) ([]*publicKey, error) {
	// Ring size check
	if len(ring) < 2 {
		return nil, ringsig.ErrRingTooSmall
	}

	// Type assert
	var ok bool
	ringPk := make([]*publicKey, len(ring))
	for i, pk := range ring {
		if ringPk[i], ok = pk.(*publicKey); !ok {
			return nil, ringsig.ErrWrongScheme
		}
	}

	// Duplication check
	for i, pk1 := range ringPk {
		for j, pk2 := range ringPk {
			if j >= i {
				break
			}
			if pk1.g2b.Equals(pk2.g2b) {
				return nil, ringsig.ErrRingDuplication
			}
		}
	}
	return ringPk, nil
}

func (s *scheme) hashMessage(message string) ([]byte, error) {
	H := s.secParams.H
	H.Reset()
	if _, err := H.Write([]byte(message)); err != nil {
		return nil, err
	}
	return H.Sum([]byte{}), nil
}

func (s *scheme) computeHashMix(temp *pbc.Element, m []byte) {
	temp.Set(s.u[0]) // Initially set to u'
	i := 0
	for j := 0; j < len(m); j++ {
		bitTester := byte(1 << 7)
		for k := 0; k < 8; k++ {
			i++
			if (m[j] & bitTester) != 0 {
				temp.Mul(temp, s.u[i])
			}
			bitTester >>= 1
		}
	}
}

func (s *scheme) Sign(message string, ring []ringsig.PublicKey, key *ringsig.KeyPair) (ringsig.Signature, error) {
	// Type assert our keys
	var ok bool
	var myPk *publicKey
	var mySk *privateKey
	if myPk, ok = key.Public.(*publicKey); !ok {
		return nil, ringsig.ErrWrongScheme
	}
	if mySk, ok = key.Private.(*privateKey); !ok {
		return nil, ringsig.ErrWrongScheme
	}

	// Type assert the ring and find the index of our key
	ringSize := len(ring)
	if ringSize < 2 {
		return nil, ringsig.ErrRingTooSmall
	}
	ringPk, err := s.checkRing(ring)
	if err != nil {
		return nil, err
	}
	myIndex := -1
	for i, pk := range ringPk {
		if myPk.g2b.Equals(pk.g2b) {
			myIndex = i
		}
	}
	if myIndex == -1 {
		return nil, ringsig.ErrNotInRing
	}

	// Compute the message hash
	m, err := s.hashMessage(message)
	if err != nil {
		return nil, err
	}

	// Allocate output
	sig := &signature{}
	sig.C = make([]*pbc.Element, ringSize)
	sig.pi = make([]*pbc.Element, ringSize)
	sig.S1 = s.pairing.NewG1()
	sig.S2 = s.pairing.NewG1()

	// Accumulator
	t := s.pairing.NewZr().Set0()

	// Temporary elements (objects are often reused for speed)
	temp1 := s.pairing.NewG1()
	temp2 := s.pairing.NewG1()
	ti := s.pairing.NewZr()

	// Compute per-signer values
	for i := 0; i < ringSize; i++ {
		sig.C[i] = s.pairing.NewG1()
		sig.pi[i] = s.pairing.NewG1()

		// Compute ti
		ti.Rand()
		t.Add(t, ti)

		// Compute C_i and pi_i
		temp1.PowerZn(s.hPower, ti)
		if i == myIndex {
			temp2.Div(ringPk[i].g2b, s.B0)
			sig.C[i].Mul(temp1, temp2)
			sig.pi[i].Set(sig.C[i])
		} else {
			temp2.Div(s.B0, ringPk[i].g2b)
			sig.pi[i].Mul(temp1, temp2)
			sig.C[i].Set(temp1)
		}
		sig.pi[i].PowZn(sig.pi[i], ti)
	}

	// Choose r
	r := ti // Reused for efficiency, renamed for clarity
	r.Rand()

	// Compute S1
	s.computeHashMix(temp1, m)
	temp1.PowZn(temp1, r)
	temp1.Mul(mySk.A2b, temp1)
	temp2.PowerZn(s.AhatPower, t)
	sig.S1.Mul(temp1, temp2)

	// Compute S2
	sig.S2.PowerZn(s.gPower, r)

	return sig, nil
}

func (s *scheme) Verify(message string, genericSig ringsig.Signature, ring []ringsig.PublicKey) bool {
	// Check types and convert ring
	var ok bool
	var sig *signature
	if sig, ok = genericSig.(*signature); !ok {
		return false
	}
	ringSize := len(ring)
	ringPk, err := s.checkRing(ring)
	if err != nil {
		return false
	}

	// Ring size should match
	if len(sig.C) != ringSize || len(sig.pi) != ringSize {
		return false
	}

	// Temporary elements
	tempG11 := s.pairing.NewG1()
	tempG12 := s.pairing.NewG1()
	tempGT1 := s.pairing.NewGT()
	tempGT2 := s.pairing.NewGT()

	// Accumulator
	B0C := s.pairing.NewG1().Set(s.B0)

	// Check proofs of per-signer ciphertext validity
	for i := 0; i < ringSize; i++ {
		tempG11.Div(ringPk[i].g2b, s.B0)
		tempG11.Div(sig.C[i], tempG11)
		tempGT1.Pair(sig.C[i], tempG11)
		tempGT2.PairerPair(s.hPairer, sig.pi[i])
		if !tempGT1.Equals(tempGT2) {
			return false
		}
		B0C.Mul(B0C, sig.C[i])
	}

	// Compute the message hash
	m, err := s.hashMessage(message)
	if err != nil {
		return false
	}

	// (1): e(S1, g)
	tempGT1.Pair(sig.S1, s.g)

	// (2): e(1/S2, u'*(prod u_j^m_j))
	tempG11.Invert(sig.S2)
	s.computeHashMix(tempG12, m)
	tempGT2.Pair(tempG11, tempG12)

	// (3): (1) * (2)
	tempGT2.Mul(tempGT1, tempGT2)

	// (4): e(A, B0*C)
	tempGT1.PairerPair(s.APairer, B0C)

	// Final check: (4) = (3) ?
	return tempGT1.Equals(tempGT2)
}
