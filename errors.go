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

import "errors"

var (
	ErrUnsupportedLevel  = errors.New("unsupported security level requested")
	ErrInvalidParameters = errors.New("scheme parameters are invalid")
	ErrWrongScheme       = errors.New("keys used in the wrong scheme")
	ErrNotInRing         = errors.New("public key is not part of the ring")
	ErrInvalidKeyPair    = errors.New("private key does not match public key")
	ErrRingTooSmall      = errors.New("ring is too small")
	ErrRingDuplication   = errors.New("ring contains duplicated key")
)
