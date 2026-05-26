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

package tpm

import (
	"errors"

	"github.com/google/go-tpm/tpm2"
)

// Sealer is an interface for wrapping and unwrapping data using the TPM.
type Sealer interface {
	// Seal seals the sensitiveData using the TPM SRK. It returns the private and public parts of the
	// sealed data (but the private data is sealed and can only be decrypted by the TPM that created
	// it). A policy can be provided to restrict the unsealing of the data.
	// If no policy is needed the function expects `nil` policy
	Seal(sensitiveData []byte, policy *tpm2.TPM2BDigest) ([]byte, []byte, error)

	// Unseal takes the private and public data, passes them to the TPM to decrypt, and returns the
	// sensitive data. Optionally, an auth session can be provided to prove fulfilment of any sealing policy.
	// If `nil` session is provided, the function will attempt to unseal without a session.
	Unseal(private []byte, public []byte, session tpm2.Session) ([]byte, error)
}

const (
	maxSealLength = 128
	maxSealCount  = 254
)

var (
	// ErrNoData indicates that the caller has supplied empty buffer
	// to the function.
	ErrNoData = errors.New("no data")
	// ErrCorruptedData indicates that the caller has supplied a corrupted
	// data buffer to the function.
	ErrCorruptedData = errors.New("supplied data is corrupt")
	// ErrTooMuchData indicates that the caller has supplied too much input
	// data to the function.
	ErrTooMuchData = errors.New("too much data")
)

// Wrap takes an arbitrary byte slice, splits it up into 128 byte chunks for
// wrapping by the TPM, then concatenates all this wrappings and returns it
// as an opaque byte slice. A policy digest can be provided to restrict the
// unsealing of the data. If no policy is needed the function expects nil
func Wrap(s Sealer, data []byte, policy *tpm2.TPM2BDigest) ([]byte, error) {
	// This allows just under 32k of data; we should only really
	// need to handle 2048 bits for RSA keys max.
	if len(data) > maxSealLength*maxSealCount {
		return nil, ErrTooMuchData
	}

	wrapped := []byte{byte((len(data) + maxSealLength - 1) / maxSealLength)}
	ofs := 0
	for ofs < len(data) {
		count := min(len(data)-ofs, maxSealLength)
		private, public, err := s.Seal(data[ofs:ofs+count], policy)
		if err != nil {
			return nil, err
		}

		// We don't expect the sealed data to be this large, but
		// check just to be sure.
		if len(private) > 255 || len(public) > 255 {
			return nil, ErrTooMuchData
		}

		wrapped = append(wrapped, byte(len(private)))
		wrapped = append(wrapped, private...)
		wrapped = append(wrapped, byte(len(public)))
		wrapped = append(wrapped, public...)

		ofs += count
	}

	return wrapped, nil
}

// Unwrap takes an opaque byte slice previously generated using Wrap(),
// splits it into a collection of sealed TPM objects, passes these to the
// TPM and returns the complete set of unwrapped data. Optionally, an auth
// session can be provided to prove fulfilment of any sealing policy.
// If `nil` session is provided, the function will attempt to unseal without
// a session.
func Unwrap(s Sealer, sealedData []byte, sess tpm2.Session) ([]byte, error) {
	// 0 + 255 are reserved counts for potential future use
	segments := sealedData[0]
	if segments == 0 || segments > maxSealCount {
		return nil, ErrCorruptedData
	}

	ofs := 1
	data := []byte{}
	for segments > 0 {
		privateLen := int(sealedData[ofs])
		ofs++
		private := sealedData[ofs : ofs+privateLen]
		ofs += privateLen
		publicLen := int(sealedData[ofs])
		ofs++
		public := sealedData[ofs : ofs+publicLen]
		ofs += publicLen

		segment, err := s.Unseal(private, public, sess)
		if err != nil {
			return nil, err
		}

		data = append(data, segment...)
		segments--
	}

	return data, nil
}
