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
	"io"
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
	// TypeUnknown is the zero value, returned by GetType when the data is too
	// short to carry a type byte. It is not a valid blob type.
	TypeUnknown Type = 0
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
	Public         []byte
	Private        []byte
	PCRs           []uint
	EncryptedSeeds []byte
	Btype          Type
	Stype          SessionType
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

// reader walks a serialized blob and refuses any read that would run past the
// end of the buffer. Every length in the wire format is taken from the buffer
// itself, so a truncated or corrupted blob can declare a field longer than
// what remains; each read is checked rather than assumed.
type reader struct {
	data []byte
	off  int
}

// remaining reports how many bytes are left to read.
func (r *reader) remaining() int {
	return len(r.data) - r.off
}

func (r *reader) readByte() (byte, error) {
	if r.remaining() < 1 {
		return 0, io.ErrUnexpectedEOF
	}
	b := r.data[r.off]
	r.off++
	return b, nil
}

func (r *reader) readUint16() (uint16, error) {
	if r.remaining() < 2 {
		return 0, io.ErrUnexpectedEOF
	}
	v := binary.LittleEndian.Uint16(r.data[r.off : r.off+2])
	r.off += 2
	return v, nil
}

// readBytes returns the next n bytes. The result aliases the input buffer, as
// it did before, so callers must not retain it beyond the lifetime of data.
func (r *reader) readBytes(n int) ([]byte, error) {
	if n < 0 || r.remaining() < n {
		return nil, io.ErrUnexpectedEOF
	}
	b := r.data[r.off : r.off+n]
	r.off += n
	return b, nil
}

// Unpack tries to deserialize a blob from a byte slice,
// and fails if the blob type is not the expected one.
//
// A truncated or otherwise malformed blob is reported as an error. Unpack does
// not panic on any input.
func Unpack(data []byte, expectedType Type) (*Blob, error) {
	r := &reader{data: data}

	btype, err := r.readByte()
	if err != nil {
		return nil, fmt.Errorf("%w: blob is empty", ErrMismatchedTypes)
	}
	if btype != byte(expectedType) {
		return nil, fmt.Errorf("%w: invalid blob type %v", ErrMismatchedTypes, btype)
	}

	var b Blob
	b.Btype = Type(btype)

	stype, err := r.readByte()
	if err != nil {
		return nil, fmt.Errorf("failed to get session type: %w", err)
	}
	b.Stype = SessionType(stype)

	pubLen, err := r.readUint16()
	if err != nil {
		return nil, fmt.Errorf("failed to get public length: %w", err)
	}
	privLen, err := r.readUint16()
	if err != nil {
		return nil, fmt.Errorf("failed to get private length: %w", err)
	}

	if b.Public, err = r.readBytes(int(pubLen)); err != nil {
		return nil, fmt.Errorf("failed to get %d byte public area: %w", pubLen, err)
	}
	if b.Private, err = r.readBytes(int(privLen)); err != nil {
		return nil, fmt.Errorf("failed to get %d byte private area: %w", privLen, err)
	}

	pcrLen, err := r.readByte()
	if err != nil {
		return nil, fmt.Errorf("failed to get PCR count: %w", err)
	}
	pcrs, err := r.readBytes(int(pcrLen))
	if err != nil {
		return nil, fmt.Errorf("failed to get %d PCR indices: %w", pcrLen, err)
	}
	b.PCRs = make([]uint, len(pcrs))
	for i, pcr := range pcrs {
		b.PCRs[i] = uint(pcr)
	}

	seedLen, err := r.readUint16()
	if err != nil {
		return nil, fmt.Errorf("failed to get encryptedSeed length: %w", err)
	}
	if b.EncryptedSeeds, err = r.readBytes(int(seedLen)); err != nil {
		return nil, fmt.Errorf("failed to get %d byte encrypted seeds: %w", seedLen, err)
	}

	return &b, nil
}

// GetType returns the blob type of a serialized blob, or TypeUnknown if the
// data is too short to carry one.
func GetType(data []byte) Type {
	if len(data) < 1 {
		return TypeUnknown
	}
	return Type(data[0])
}

func packInt16(d uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, d)
	return b
}
