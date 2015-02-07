# Ringsig [![Build Status](https://travis-ci.org/Nik-U/ringsig.svg)](https://travis-ci.org/Nik-U/ringsig) [![GoDoc](https://godoc.org/github.com/Nik-U/ringsig?status.svg)](https://godoc.org/github.com/Nik-U/ringsig)

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

## Implementations
Currently, the ringsig package only includes one ring signature scheme.
This scheme was published by Shacham and Waters in "Efficient Ring
Signatures without Random Oracles". It provides full-key disclosure
anonymity and insider corruption unforgeability while also being provably
secure in the standard model. In this implementation, it relies on three
complexity assumptions: integer factorization in finite fields,
computational Diffie-Hellman in prime order cyclic subgroups of elliptic
curves, and subgroup decision in composite elliptic curves.

## Dependencies
Ringsig makes use of the PBC Go wrapper. Installation of the PBC Go wrapper is
non-trivial. For instructions, see https://godoc.org/github.com/Nik-U/pbc.

## Documentation
For additional documentation, see https://godoc.org/github.com/Nik-U/ringsig.
