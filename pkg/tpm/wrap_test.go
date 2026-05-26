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
	"bytes"
	"fmt"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func reverse(data []byte) []byte {
	var reversed []byte
	for i := len(data) - 1; i >= 0; i-- {
		reversed = append(reversed, data[i])
	}
	return reversed
}

type testSealer struct{}

func (testSealer) Seal(sensitiveData []byte, _ *tpm2.TPM2BDigest) ([]byte, []byte, error) {
	return reverse(sensitiveData), sensitiveData, nil
}

func (testSealer) Unseal(private []byte, public []byte, session tpm2.Session) ([]byte, error) {
	data := reverse(private)
	if !bytes.Equal(data, public) {
		return nil, fmt.Errorf("unseal failed: public data does not match private data %q != %q", data, public)
	}
	return data, nil
}

func TestWrapUnwrap(t *testing.T) {
	data := bytes.Repeat([]byte("effici3ncy"), 32)
	ts := testSealer{}
	wrapped, err := Wrap(ts, data, nil)
	if err != nil {
		t.Fatalf("Wrap() failed: %v", err)
	}
	unwrapped, err := Unwrap(ts, wrapped, nil)
	if err != nil {
		t.Fatalf("Unwrap() failed: %v", err)
	}
	if !bytes.Equal(data, unwrapped) {
		t.Fatalf("Unwrap() failed: unwrapped data does not match original data %q != %q", data, unwrapped)
	}
}
