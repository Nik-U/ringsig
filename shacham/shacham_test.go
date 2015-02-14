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

package shacham_test

import (
	"testing"

	"github.com/Nik-U/ringsig"
	"github.com/Nik-U/ringsig/internal/rsutil"
	"github.com/Nik-U/ringsig/shacham"
)

func TestShacham1(t *testing.T) {
	rsutil.TestScheme(t, true, func() (ringsig.Scheme, error) { return shacham.New(1) }, shacham.Load)
}

func TestShacham2(t *testing.T) {
	rsutil.TestScheme(t, true, func() (ringsig.Scheme, error) { return shacham.New(2) }, shacham.Load)
}

func TestShacham3(t *testing.T) {
	rsutil.TestScheme(t, true, func() (ringsig.Scheme, error) { return shacham.New(3) }, shacham.Load)
}

func newShachamOrPanic(securityFactor uint8) ringsig.Scheme {
	scheme, err := shacham.New(securityFactor)
	if err != nil {
		panic(err)
	}
	return scheme
}

func BenchmarkShacham1KeyGen(b *testing.B) { rsutil.BenchmarkKeyGen(b, newShachamOrPanic(1)) }
func BenchmarkShacham2KeyGen(b *testing.B) { rsutil.BenchmarkKeyGen(b, newShachamOrPanic(2)) }
func BenchmarkShacham3KeyGen(b *testing.B) { rsutil.BenchmarkKeyGen(b, newShachamOrPanic(3)) }
func BenchmarkShacham1Sign(b *testing.B)   { rsutil.BenchmarkSign(b, newShachamOrPanic(1)) }
func BenchmarkShacham2Sign(b *testing.B)   { rsutil.BenchmarkSign(b, newShachamOrPanic(2)) }
func BenchmarkShacham3Sign(b *testing.B)   { rsutil.BenchmarkSign(b, newShachamOrPanic(3)) }
func BenchmarkShacham1Verify(b *testing.B) { rsutil.BenchmarkVerify(b, newShachamOrPanic(1)) }
func BenchmarkShacham2Verify(b *testing.B) { rsutil.BenchmarkVerify(b, newShachamOrPanic(2)) }
func BenchmarkShacham3Verify(b *testing.B) { rsutil.BenchmarkVerify(b, newShachamOrPanic(3)) }
