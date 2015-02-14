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

package ringsig

import (
	"io"

	"github.com/Nik-U/ringsig/internal/genutil"
)

// Exportable represents a type that can be encoded into a binary stream. They
// can be written to a Writer or transformed directly into bytes.
type Exportable interface {
	io.WriterTo
	Bytes() []byte
}

// PublicKey represents a public key for a ring signature scheme. Public keys
// are used to form rings, which in turn are used to sign and verify signatures.
// Every public key has an associated private key.
type PublicKey interface {
	Exportable
	Equals(PublicKey) bool
}

// PrivateKey represents a private key for a ring signature scheme. Private keys
// are used to create signatures.
type PrivateKey interface {
	Exportable
}

// KeyPair is the combination of a public key and the associated private key. It
// implements Exportable.
type KeyPair struct {
	Public  PublicKey
	Private PrivateKey
}

// Signature represents a digital signature of a message under a ring signature
// scheme.
type Signature interface {
	Exportable
}

// Scheme represents a ring signature scheme. All ring signature operations must
// be performed in the context of a scheme, and all protocol participants must
// share the same scheme.
//
// Schemes can either be generated or loaded. Scheme generation is performed by
// calling a New* function for the desired scheme — a task normally performed by
// a trusted authority. The scheme can then be exported and distributed to the
// protocol participants, who duplicate it using a Load* function.
//
// Key generation occurs by calling KeyGen on the scheme. The resulting key pair
// can be saved, and the public key can be independently exported for
// transmission to other parties.
//
// Signatures are generated using the Sign method. Sign will return a signature
// or an error in case of failure. Rings must have at least two public keys in
// them, and one of the public keys must match the signing key pair. There must
// also be no duplication of public keys in the ring.
//
// Signatures are verified using the Verify method. The given ring must be the
// same as the one used to sign the message (e.g., it may not be a subset or
// superset).
//
// All keys and signatures must be loaded in the context of a scheme using the
// Load* methods.
type Scheme interface {
	Exportable

	KeyGen() *KeyPair
	Sign(message string, ring []PublicKey, key *KeyPair) (Signature, error)
	Verify(message string, signature Signature, ring []PublicKey) bool

	LoadPublicKey(io.Reader) (PublicKey, error)
	LoadPrivateKey(io.Reader) (PrivateKey, error)
	LoadKeyPair(io.Reader) (*KeyPair, error)
	LoadSignature(io.Reader) (Signature, error)
}

func (pair *KeyPair) WriteTo(w io.Writer) (n int64, err error) {
	if n, err = pair.Public.WriteTo(w); err != nil {
		return
	}
	n2, err := pair.Private.WriteTo(w)
	n += n2
	return
}

func (pair *KeyPair) Bytes() []byte { return genutil.ConvertToBytes(pair) }
