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

	"github.com/facebookincubator/iks/pkg/blob"
)

// ReadKeyParts reads the public and private parts of a key blob.
func ReadKeyParts(keyBlob []byte) (public, private []byte, err error) {
	b, err := blob.Unpack(keyBlob, blob.KeyTypeTPM)
	if errors.Is(err, blob.ErrMismatchedTypes) {
		return nil, nil, ErrCorruptedData
	} else if err != nil {
		return nil, nil, err
	}

	return b.Public, b.Private, nil
}
