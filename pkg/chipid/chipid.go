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
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/google/go-eventlog/register"
	"github.com/google/go-eventlog/tcg"
)

// Vendor identifies the CPU vendor and technology that produced a chip ID.
type Vendor string

const (
	VendorAMDSEVSNP Vendor = "amd-sev-snp"
)

// Result contains a chip identifier along with its vendor/technology.
type Result struct {
	Vendor Vendor
	ID     []byte
}

type extractor interface {
	Extract() (*Result, error)
}

var (
	cpuVendorID       string
	selectedExtractor extractor
)

const (
	cpuInfoPath      = "/proc/cpuinfo"
	uefiEventLogPath = "/sys/kernel/security/tpm0/binary_bios_measurements"

	// amdChipIDSize is the fixed size of an AMD SEV-SNP ChipID (64 bytes).
	// https://www.ietf.org/archive/id/draft-deeglaze-amd-sev-snp-corim-profile-02.html#section-3.1.2.1-23
	amdChipIDSize = 64
)

// ivesTag is the 4-byte "IVES" header that prefixes AMD SEV-SNP ChipID
// payloads in the PCR 1 UEFI event log.
var ivesTag = []byte{0x49, 0x56, 0x45, 0x53}

func init() {
	// amd64 is just Go's name for the x86-64 ISA, thus we need to check
	// the CPU vendor separately below from /proc/cpuinfo.
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return
	}

	cpuVendorID = linuxCPUVendor()
	// AuthenticAMD is the known a 12-byte processor manufacturer ID for AMD.
	if cpuVendorID == "AuthenticAMD" {
		selectedExtractor = &amdSEVSNPExtractor{}
	}
}

func linuxCPUVendor() string {
	data, err := os.ReadFile(cpuInfoPath)
	if err != nil {
		return ""
	}
	return parseCPUVendor(string(data))
}

// parseCPUVendor returns the first vendor_id value from /proc/cpuinfo content.
// /proc/cpuinfo repeats vendor_id per logical CPU; we return the first.
func parseCPUVendor(content string) string {
	for line := range strings.SplitSeq(content, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(key) != "vendor_id" {
			continue
		}
		return strings.TrimSpace(value)
	}
	return ""
}

// Get returns a chip identifier from a platform-specific source.
func Get() (*Result, error) {
	if selectedExtractor == nil {
		return nil, fmt.Errorf("no chip ID extractor registered for %s/%s vendor_id=%s", runtime.GOOS, runtime.GOARCH, cpuVendorID)
	}

	result, err := selectedExtractor.Extract()
	if err != nil {
		return nil, fmt.Errorf("no chip ID found: %w", err)
	}
	if result == nil {
		return nil, errors.New("chip ID extractor returned nil result")
	}
	return result, nil
}

type amdSEVSNPExtractor struct{}

func (e *amdSEVSNPExtractor) Extract() (*Result, error) {
	data, err := readSEVChipID()
	if err == nil {
		return &Result{Vendor: VendorAMDSEVSNP, ID: data}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		// We allow fall through if there's no /dev/sev device, but
		// if there's a problem with it, bubble it up instead.
		return nil, fmt.Errorf("failed to read ID from ASP: %w", err)
	}

	data, err = os.ReadFile(uefiEventLogPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read UEFI event log: %w", err)
	}

	eventLog, err := tcg.ParseEventLog(data, tcg.ParseOpts{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse event log: %w", err)
	}

	result, err := extractAMDChipID(eventLog.Events(register.HashSHA256))
	if err == nil {
		return result, nil
	}

	// Fall back to direct PSP access via PCIe. This works even when SEV is
	// disabled in BIOS or TPM event log is unavailable, but is riskier as
	// as we're poking the device directly without any locking with
	// potential kernel users.
	result, err = readSEVChipIDDirect()
	if err != nil {
		return nil, fmt.Errorf("failed direct ChipID read from SP: %w", err)
	}

	return result, nil
}

// extractAMDChipID returns the first AMD SEV-SNP ChipID found in PCR 1 events.
func extractAMDChipID(events []tcg.Event) (*Result, error) {
	for _, event := range events {
		if event.Index != 1 {
			continue
		}
		id, err := ParseAMDChipIDPayload(event.RawData())
		if err != nil {
			continue
		}
		return &Result{Vendor: VendorAMDSEVSNP, ID: id}, nil
	}
	return nil, errors.New("AMD SEV-SNP ChipID event not found in PCR1 event log")
}

// ParseAMDChipIDPayload extracts the first 64-byte AMD SEV-SNP ChipID from a
// PCR 1 UEFI event payload. The expected layout is:
//
//	bytes 0-3:  "IVES" tag
//	bytes 4-7:  total length in bytes (little-endian uint32), e.g.
//	            0x80 0x00 0x00 0x00 for two CPUs on a multi-socket host
//	bytes 8+:   one 64-byte ChipID per socket
func ParseAMDChipIDPayload(raw []byte) ([]byte, error) {
	if len(raw) < 8+amdChipIDSize {
		return nil, fmt.Errorf("payload too short: %d bytes", len(raw))
	}
	if !bytes.Equal(raw[0:4], ivesTag) {
		return nil, errors.New("payload missing IVES tag")
	}
	return raw[8 : 8+amdChipIDSize], nil
}
