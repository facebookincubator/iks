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

//go:build linux && amd64

package chipid

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckDMAChipID(t *testing.T) {
	realID := bytes.Repeat([]byte{0xAB}, amdChipIDSize)

	tests := []struct {
		name    string
		buf     []byte
		idLen   int
		wantErr string
	}{
		{"valid_id", realID, amdChipIDSize, ""},
		{"short_id_is_accepted", realID, 8, ""},
		{
			"untouched_buffer_still_holds_sentinel",
			bytes.Clone(aspChipIDSentinel),
			amdChipIDSize,
			"without writing the ChipID buffer",
		},
		{"all_zero_id", make([]byte, amdChipIDSize), amdChipIDSize, "all-zero ChipID"},
		{
			"zero_prefix_with_sentinel_tail",
			append(make([]byte, 8), aspChipIDSentinel[8:]...),
			8,
			"all-zero ChipID",
		},
		{"zero_length", realID, 0, "invalid chip ID length"},
		{"negative_length", realID, -1, "invalid chip ID length"},
		{"length_beyond_buffer", realID, amdChipIDSize + 1, "invalid chip ID length"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkDMAChipID(tt.buf, tt.idLen)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestASPChipIDSentinelIsBufferSized(t *testing.T) {
	assert.Len(t, aspChipIDSentinel, amdChipIDSize)
}
