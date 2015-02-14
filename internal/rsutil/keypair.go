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

package rsutil

import (
	"io"

	"github.com/Nik-U/ringsig"
)

func LoadKeyPair(scheme ringsig.Scheme, r io.Reader) (*ringsig.KeyPair, error) {
	var err error
	p := &ringsig.KeyPair{}
	if p.Public, err = scheme.LoadPublicKey(r); err != nil {
		return nil, err
	}
	if p.Private, err = scheme.LoadPrivateKey(r); err != nil {
		return nil, err
	}
	return p, nil
}
