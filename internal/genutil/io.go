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

package genutil

import (
	"bytes"
	"encoding/gob"
	"io"

	"github.com/Nik-U/pbc"
)

func ConvertToBytes(wt io.WriterTo) []byte {
	buf := new(bytes.Buffer)
	wt.WriteTo(buf)
	return buf.Bytes()
}

type gobWriter struct {
	w     io.Writer
	enc   *gob.Encoder
	count int64
	err   error
}

func NewGobWriter(w io.Writer) *gobWriter {
	gw := &gobWriter{w: w}
	gw.enc = gob.NewEncoder(gw)
	return gw
}

func (gw *gobWriter) Write(p []byte) (int, error) {
	if gw.err != nil {
		return len(p), nil
	}
	n, err := gw.w.Write(p)
	gw.count += int64(n)
	gw.err = err
	return n, err
}

func (gw *gobWriter) Encode(e interface{}) {
	if gw.err == nil {
		err := gw.enc.Encode(e)
		if err != nil {
			gw.err = err
		}
	}
}

func (gw *gobWriter) Count() int64 { return gw.count }
func (gw *gobWriter) Err() error   { return gw.err }

type gobReader struct {
	dec *gob.Decoder
	err error
}

func NewGobReader(r io.Reader) *gobReader {
	return &gobReader{dec: gob.NewDecoder(r)}
}

func (gr *gobReader) Decode(e interface{}) bool {
	if gr.err == nil {
		gr.err = gr.dec.Decode(e)
	}
	return gr.err == nil
}

func (gr *gobReader) DecodeElement(e *pbc.Element) bool {
	var buf []byte
	if !gr.Decode(&buf) {
		return false
	}
	e.SetCompressedBytes(buf)
	return true
}

func (gr *gobReader) Err() error { return gr.err }
