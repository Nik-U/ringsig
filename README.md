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
Ring signature implementations are placed in subpackages. The rationale for
this is that some implementations may require complex dependencies that not
all clients need.

## Documentation
For additional documentation, see https://godoc.org/github.com/Nik-U/ringsig.
