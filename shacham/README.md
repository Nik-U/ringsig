# Shacham-Waters (Part of Ringsig)

Package shacham implements efficient Shacham-Waters ring signatures. This
scheme was published by Shacham and Waters in "Efficient Ring Signatures
without Random Oracles". It provides full-key disclosure anonymity and
insider corruption unforgeability while also being provably secure in the
standard model. In this implementation, it relies on three complexity
assumptions: integer factorization, computational Diffie-Hellman in prime
order cyclic subgroups of elliptic curves, and subgroup decision in
composite elliptic curves.

## Dependencies
This package makes use of the PBC Go wrapper. Installation of the PBC Go wrapper
is non-trivial. For instructions, see https://godoc.org/github.com/Nik-U/pbc.

## Documentation
For additional documentation, see
https://godoc.org/github.com/Nik-U/ringsig/shacham.