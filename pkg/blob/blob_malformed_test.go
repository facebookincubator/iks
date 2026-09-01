// Copyright (c) Facebook, Inc. and its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package blob

import (
	"testing"
)

// Every length in the blob format is read out of the blob itself, so a
// truncated or corrupted one can declare a field longer than what remains.
// Each case below is the shortest input that reaches a particular read.
func TestUnpackMalformed(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"type byte only", []byte{byte(WrapTypeTPM)}},
		{"truncated before public length", []byte{byte(WrapTypeTPM), byte(NullSession), 0}},
		{"truncated before private length", []byte{byte(WrapTypeTPM), byte(NullSession), 0, 0, 0}},
		{"public length exceeds buffer", []byte{byte(WrapTypeTPM), byte(NullSession), 0xff, 0xff, 0, 0}},
		{"private length exceeds buffer", []byte{byte(WrapTypeTPM), byte(NullSession), 0, 0, 0xff, 0xff}},
		{"truncated before PCR count", []byte{byte(WrapTypeTPM), byte(NullSession), 0, 0, 0, 0}},
		{"PCR count exceeds buffer", []byte{byte(WrapTypeTPM), byte(NullSession), 0, 0, 0, 0, 0xff}},
		{"truncated before seed length", []byte{byte(WrapTypeTPM), byte(NullSession), 0, 0, 0, 0, 0}},
		{"seed length exceeds buffer", []byte{byte(WrapTypeTPM), byte(NullSession), 0, 0, 0, 0, 0, 0xff, 0xff}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Unpack panicked on %d bytes: %v", len(tc.data), r)
				}
			}()
			if _, err := Unpack(tc.data, WrapTypeTPM); err == nil {
				t.Fatalf("Unpack accepted malformed input of %d bytes", len(tc.data))
			}
		})
	}
}

// A blob that is well formed apart from a short tail must still be rejected
// rather than silently returning a partial result.
func TestUnpackTruncatedTail(t *testing.T) {
	full := Pack(&Blob{
		Btype:          WrapTypeTPM,
		Stype:          PCRSession,
		Public:         []byte("public area"),
		Private:        []byte("private area"),
		PCRs:           []uint{0, 1, 7},
		EncryptedSeeds: []byte("seeds"),
	})

	for n := 0; n < len(full); n++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Unpack panicked on a %d byte prefix: %v", n, r)
				}
			}()
			if _, err := Unpack(full[:n], WrapTypeTPM); err == nil {
				t.Fatalf("Unpack accepted a %d byte prefix of a %d byte blob", n, len(full))
			}
		}()
	}

	if _, err := Unpack(full, WrapTypeTPM); err != nil {
		t.Fatalf("Unpack rejected the complete blob: %v", err)
	}
}

func TestGetTypeShortInput(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("GetType panicked on empty input: %v", r)
		}
	}()
	if got := GetType(nil); got != TypeUnknown {
		t.Fatalf("GetType(nil) = %v, want TypeUnknown", got)
	}
	if got := GetType([]byte{}); got != TypeUnknown {
		t.Fatalf("GetType(empty) = %v, want TypeUnknown", got)
	}
	if got := GetType([]byte{byte(KeyTypeTPM)}); got != KeyTypeTPM {
		t.Fatalf("GetType = %v, want KeyTypeTPM", got)
	}
}

// FuzzUnpack asserts the only contract that matters for a parser fed data it
// did not produce: return, never panic.
func FuzzUnpack(f *testing.F) {
	f.Add(Pack(&Blob{Btype: WrapTypeTPM, Stype: NullSession}))
	f.Add(Pack(&Blob{
		Btype:          WrapTypeTPM,
		Stype:          PCRSession,
		Public:         []byte("pub"),
		Private:        []byte("priv"),
		PCRs:           []uint{0, 7},
		EncryptedSeeds: []byte("seed"),
	}))
	f.Add([]byte{byte(WrapTypeTPM)})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := Unpack(data, WrapTypeTPM)
		if err != nil {
			return
		}
		// A blob that unpacked must survive a round trip through Pack.
		if _, err := Unpack(Pack(b), WrapTypeTPM); err != nil {
			t.Fatalf("re-packing an accepted blob produced one that will not unpack: %v", err)
		}
	})
}
