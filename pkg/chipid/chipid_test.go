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

package chipid

import (
	"bytes"
	"testing"

	"github.com/google/go-eventlog/tcg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCPUVendor(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{"amd", "processor\t: 0\nvendor_id\t: AuthenticAMD\ncpu family\t: 25\n", "AuthenticAMD"},
		{"multi_socket_returns_first", "vendor_id\t: AuthenticAMD\n\nvendor_id\t: GenuineIntel\n", "AuthenticAMD"},
		{"missing_vendor_id", "processor\t: 0\ncpu family\t: 25\n", ""},
		{"empty", "", ""},
		{"extra_whitespace_tolerated", "  vendor_id  :    AuthenticAMD   \n", "AuthenticAMD"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseCPUVendor(tt.content))
		})
	}
}

// makeIVESPayload assembles an IVES-tagged payload carrying the given chip IDs.
// The 4-byte length field is left as zero — ParseAMDChipIDPayload doesn't read it.
func makeIVESPayload(chips ...[]byte) []byte {
	out := append([]byte{}, ivesTag...)
	out = append(out, 0, 0, 0, 0)
	for _, c := range chips {
		out = append(out, c...)
	}
	return out
}

func TestParseAMDChipIDPayload(t *testing.T) {
	chipA := bytes.Repeat([]byte{0xAA}, amdChipIDSize)
	chipB := bytes.Repeat([]byte{0xBB}, amdChipIDSize)

	tests := []struct {
		name    string
		raw     []byte
		want    []byte
		wantErr bool
	}{
		{"single_socket", makeIVESPayload(chipA), chipA, false},
		{"multi_socket_returns_first", makeIVESPayload(chipA, chipB), chipA, false},
		{"missing_ives_tag", append([]byte("FAKE\x00\x00\x00\x00"), chipA...), nil, true},
		{"truncated", append([]byte{}, ivesTag...), nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAMDChipIDPayload(tt.raw)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExtractAMDChipID(t *testing.T) {
	chip := bytes.Repeat([]byte{0xAA}, amdChipIDSize)
	valid := makeIVESPayload(chip)

	tests := []struct {
		name    string
		events  []tcg.Event
		want    []byte
		wantErr bool
	}{
		{
			name:   "happy_path",
			events: []tcg.Event{{Index: 1, Data: valid}},
			want:   chip,
		},
		{
			name: "no_pcr_1_event",
			events: []tcg.Event{
				{Index: 0, Data: valid},
				{Index: 7, Data: valid},
			},
			wantErr: true,
		},
		{
			name:    "no_events",
			events:  nil,
			wantErr: true,
		},
		{
			name: "skip_pcr_1_event_with_bad_payload",
			events: []tcg.Event{
				{Index: 1, Data: []byte("garbage")},
				{Index: 1, Data: valid},
			},
			want: chip,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractAMDChipID(tt.events)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, VendorAMDSEVSNP, got.Vendor)
			assert.Equal(t, tt.want, got.ID)
		})
	}
}
