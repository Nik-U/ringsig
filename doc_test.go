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
	"github.com/Nik-U/ringsig"
	"github.com/Nik-U/ringsig/shacham"
)

func Example() {
	// Generate new scheme parameters
	scheme, _ := shacham.New(2)

	// In the real world, these parameters would be saved using scheme.WriteTo
	// and then loaded by the clients using shacham.Load.

	// Two clients generate key pairs
	alice := scheme.KeyGen()
	bob := scheme.KeyGen()

	// We will sign over the ring of the two users. In general, higher level
	// communication protocols will somehow specify the ring used to sign the
	// message (either explicitly or implicitly).
	ring := []ringsig.PublicKey{alice.Public, bob.Public}

	// Alice signs a message intended for Bob
	sig, _ := scheme.Sign("message", ring, alice)

	// Bob verifies the signature
	if scheme.Verify("message", sig, ring) {
		// Both Alice and Bob are now convinced that Alice signed the message.
		// However, nobody else can be convinced of this cryptographically.
	}
}
