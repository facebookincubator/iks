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
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	// ErrMismatchedTypes is returned when the blob type is not the same as the expected type.
	ErrMismatchedTypes = errors.New("mismatched types")
)

// SessionType is the type of session associated with the created TPM object.
type SessionType byte

const (
	// NullSession represents a null session.
	NullSession SessionType = iota + 1
	// AuthSession represents a regular password session.
	AuthSession
	// PCRSession represents a session with PCRs policy.
	PCRSession
)

// Type represents blob type.
type Type byte

const (
	// WrapTypeSW represents software wrapped data.
	WrapTypeSW Type = 1
	// WrapTypeTPM represents TPM wrapped data.
	WrapTypeTPM Type = 2
	// KeyTypeSW represents software generated key blob.
	KeyTypeSW Type = 3
	// KeyTypeTPM represents TPM generated key blob.
	KeyTypeTPM Type = 4
	// ImportTypeSW represents importable software wrapped data.
	ImportTypeSW Type = 5
	// ImportTypeTPM represents externally wrapped, TPM importable data.
	ImportTypeTPM Type = 6
	// KeyTypeCryptoOracle represents CryptoOracle generated key blob.
	KeyTypeCryptoOracle Type = 7
	// WrapTypeEATS represents EATS wrapped data.
	WrapTypeEATS Type = 8
)

// Blob is a struct to represent blobs created by IKS
// (e.g. wrapped blobs, signing key blobs).
type Blob struct {
	Btype           Type
	Public, Private []byte
	Stype           SessionType
	PCRs            []uint
	// this is needed to validate/unwrap imported object.
	EncryptedSeeds []byte
}

// Pack serializes a blob into a byte slice.
func Pack(b *Blob) []byte {
	// minimum blob size = 9
	// 1 byte for blob type + 1 byte for session type + 1 byte for PCRs length
	// 3 * 2 bytes for lengths of (public, private, encrypted seeds).
	expectedCap := 9 + len(b.Public) + len(b.Private) + len(b.PCRs) + len(b.EncryptedSeeds)
	buffer := make([]byte, 0, expectedCap)

	buffer = append(buffer, byte(b.Btype))
	buffer = append(buffer, byte(b.Stype))
	pubLen, privLen := uint16(len(b.Public)), uint16(len(b.Private))
	buffer = append(buffer, packInt16(pubLen)...)
	buffer = append(buffer, packInt16(privLen)...)
	buffer = append(buffer, b.Public...)
	buffer = append(buffer, b.Private...)
	buffer = append(buffer, byte(len(b.PCRs)))
	for _, pcr := range b.PCRs {
		buffer = append(buffer, byte(pcr))
	}
	seedLen := uint16(len(b.EncryptedSeeds))
	buffer = append(buffer, packInt16(seedLen)...)
	buffer = append(buffer, b.EncryptedSeeds...)

	return buffer
}

// Unpack tries to deserialize a blob from a byte slice,
// and fails if the blob type is not the expected one.
func Unpack(data []byte, expectedType Type) (*Blob, error) {
	if len(data) < 1 || data[0] != byte(expectedType) {
		return nil, fmt.Errorf("%w: invalid blob type %v", ErrMismatchedTypes, data[0])
	}

	var b Blob
	b.Btype = Type(data[0])
	b.Stype = SessionType(data[1])
	offset := 2

	pubLen, err := unpackInt16(data[offset : offset+2])
	if err != nil {
		return nil, err
	}
	privLen, err := unpackInt16(data[offset+2 : offset+4])
	if err != nil {
		return nil, err
	}
	offset += 4
	b.Public = data[offset : offset+int(pubLen)]
	offset += int(pubLen)
	b.Private = data[offset : offset+int(privLen)]
	offset += int(privLen)

	pcrLen := int(data[offset])
	offset++
	b.PCRs = make([]uint, pcrLen)
	for i := range pcrLen {
		b.PCRs[i] = uint(data[offset])
		offset++
	}
	seedLen, err := unpackInt16(data[offset : offset+2])
	if err != nil {
		return nil, fmt.Errorf("failed to get encryptedSeed length: %w", err)
	}
	offset += 2
	b.EncryptedSeeds = data[offset : offset+int(seedLen)]

	return &b, nil
}

// GetType returns the blob type of a serialized blob.
func GetType(data []byte) Type {
	return Type(data[0])
}

func packInt16(d uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, d)
	return b
}

func unpackInt16(b []byte) (uint16, error) {
	if len(b) != 2 {
		return 0, fmt.Errorf("invalid int16 length: %d", len(b))
	}
	return binary.LittleEndian.Uint16(b), nil
}
