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
	"crypto/rand"
	"fmt"
	mrand "math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBlobPackUnpack(t *testing.T) {
	testCases := []struct {
		name string
		b    Blob
	}{
		{"empty blob", Blob{}},
		{"wrapped data blob", Blob{
			Btype:   WrapTypeSW,
			Private: generateRandomBytes(t, 125),
		}},
		{"wrapped data blob with PCRs", Blob{
			Btype:   WrapTypeTPM,
			Private: generateRandomBytes(t, 125),
			Stype:   PCRSession,
			PCRs:    []uint{4, 5},
		}},
		{"key blob", Blob{
			Btype:   KeyTypeTPM,
			Public:  generateRandomBytes(t, 125),
			Private: generateRandomBytes(t, 125),
		}},
		{"imported blob", Blob{
			Btype:          ImportTypeTPM,
			Public:         generateRandomBytes(t, 125),
			Private:        generateRandomBytes(t, 125),
			Stype:          PCRSession,
			PCRs:           []uint{4, 5},
			EncryptedSeeds: generateRandomBytes(t, 125),
		}},
	}

	var fields []func(*Blob) = []func(*Blob){
		func(b *Blob) {
			n := mrand.Intn(255)
			b.Private = generateRandomBytes(t, n)
		},
		func(b *Blob) {
			n := mrand.Intn(255)
			b.Public = generateRandomBytes(t, n)
		},
		func(b *Blob) {
			b.PCRs = []uint{4, 5, 2, 1}
		},
		func(b *Blob) {
			n := mrand.Intn(255)
			b.EncryptedSeeds = generateRandomBytes(t, n)
		},
	}

	// Add test case of all combination of nullable fields
	count := 1 << len(fields)
	for i := 1; i < count; i++ {
		// count represents a choice of fields
		// e.g. 0b0101 means set both Private and PCRs
		var b Blob
		for j, setField := range fields {
			if i&(1<<j) != 0 {
				setField(&b)
			}
		}
		testCases = append(testCases, struct {
			name string
			b    Blob
		}{
			fmt.Sprintf("random test case %4b", i),
			b,
		})
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			packed := Pack(&tc.b)

			unpacked, err := Unpack(packed, tc.b.Btype)
			assert.Nil(t, err)
			assertEqualBlob(t, tc.b, *unpacked)
		})
	}
}

func TestUnpackWrongBlobType(t *testing.T) {
	b := Blob{
		Btype:   WrapTypeSW,
		Private: generateRandomBytes(t, 12),
	}
	packed := Pack(&b)

	bParsed, err := Unpack(packed, WrapTypeTPM)
	assert.NotNil(t, err)
	assert.Nil(t, bParsed)

	assert.ErrorIs(t, err, ErrMismatchedTypes)
}

func assertEqualBlob(t *testing.T, a, b Blob) {
	assert.Equal(t, a.Btype, b.Btype)
	assert.Equal(t, a.Stype, b.Stype)
	assert.Equal(t, len(a.Public), len(b.Public))
	if len(a.Public) != 0 {
		assert.Equal(t, a.Public, b.Public)
	}
	assert.Equal(t, len(a.Private), len(b.Private))
	if len(a.Private) != 0 {
		assert.Equal(t, a.Private, b.Private)
	}
	assert.Equal(t, len(a.PCRs), len(b.PCRs))
	if len(a.PCRs) != 0 {
		assert.Equal(t, a.PCRs, b.PCRs)
	}
	assert.Equal(t, len(a.EncryptedSeeds), len(b.EncryptedSeeds))
	if len(a.EncryptedSeeds) != 0 {
		assert.Equal(t, a.EncryptedSeeds, b.EncryptedSeeds)
	}
}

func generateRandomBytes(t *testing.T, n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	assert.Nil(t, err)
	return b
}
