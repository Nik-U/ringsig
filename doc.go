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
	Package ringsig implements ring signatures in Go. Ring signatures are a
	special type of digital signature that prove a message was signed by one of
	a set of possible signers, without revealing which member of the set
	created the signature. Ring signatures were originally proposed by Rivest,
	Shamir, and Tauman in the paper titled "How to Leak a Secret".

	Ring signatures can be used to construct many interesting schemes. One
	traditional example is leaking secret documents while protecting the
	identity of the leaker. Another example is the sender of a message proving
	their identity to the recipient without allowing the recipient to
	convincingly convey this proof to a third party.

	Overview

	A ring signature scheme consists of four algorithms: setup, key generation,
	signing, and verification.

	The setup phase occurs once, before the deployment of the scheme. It
	produces scheme-specific parameters that must be shared with all
	participants of the system. The setup algorithm is of the following form:

		params ← setup()

	These parameters must be passed to the other functions of the scheme. Some
	schemes do not require the setup phase (i.e., their parameters are empty).

	The key generation algorithm is of the following form:

		(privKey, pubKey) ← keyGen(params)

	keyGen returns a private key and the corresponding public key.

	The signing algorithm is of the following form:

		signature ← sign(params, message, ring, privKey)

	sign returns a signature for the given message. ring is a set of public
	keys, and privKey is a secret key corresponding to one of the public keys
	in ring.

	The verification algorithm is of the following form:

		ok ← verify(params, message, signature, ring)

	verify returns true if the given signature is valid for the given message.
	The signature is valid if it was produced by any secret key corresponding
	to a public key in the ring.

	All ring signature schemes share the property that it is computationally
	infeasible, given only a message, signature, and ring, to determine which
	secret key was used to produce the signature.

	Security Properties

	Some ring signature schemes provide additional security properties or
	introduce some additional limitations (usually in order to improve
	efficiency or provable security). Schemes might exhibit one or more of the
	following characteristics:

	• Chosen-key anonymity: the scheme preserves anonymity even when only two
	members of the ring are honest (i.e., not colluding with the adversary).

	• Full-key disclosure anonymity: the scheme preserves anonymity even when
	the secret keys of all users are disclosed to the adversary after the
	signature has been produced.

	• Fixed-ring unforgeability: an adversary cannot produce a signature for a
	message that verifies against a given ring, even when they can receive
	valid signatures for selected (different) messages in the same ring.

	• Chosen-subring unforgeability: the same as fixed-ring unforgeability, but
	both the final output ring and the signing oracle rings can be subrings
	chosen by the adversary.

	• Insider corruption unforgeability: the same as chosen-subring
	unforgeability, but the adversary can also corrupt honest users, thereby
	revealing their secret keys. The adversary should not be able to produce a
	valid message for a subring that does not contain a corrupted user.

	• c-user: the ring signature only operates on fixed rings of size c.

	• Identity-based: public keys are derived solely from plaintext strings,
	allowing users to be included in the ring even if they do not participate
	in the signature scheme.

	Ring signature schemes may also prove their security properties in
	different models. For example, some schemes are only secure in the random
	oracle model, while others are secure in the standard model. Different may
	schemes also require different infeasibility assumptions.

	For additional information about ring signature properties, see "Ring
	Signatures: Stronger Definitions, and Constructions Without Random Oracles"
	from Bender, Katz, and Morselli.

	Implementations

	Currently, the ringsig package only includes one ring signature scheme.
	This scheme was published by Shacham and Waters in "Efficient Ring
	Signatures without Random Oracles". It provides full-key disclosure
	anonymity and insider corruption unforgeability while also being provably
	secure in the standard model. In this implementation, it relies on three
	complexity assumptions: integer factorization, computational Diffie-Hellman
	in prime order cyclic subgroups of elliptic curves, and subgroup decision
	in composite elliptic curves.

	License

	This package is free software: you can redistribute it and/or modify it
	under the terms of the GNU Lesser General Public License as published by
	the Free Software Foundation, either version 3 of the License, or (at your
	option) any later version.

	For additional details, see the COPYING and COPYING.LESSER files.
*/
package ringsig
