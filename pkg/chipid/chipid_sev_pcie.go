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
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/edsrzf/mmap-go"
	"golang.org/x/sys/unix"
)

// ASP PCIe device constants from D106112306 and AMD SEV API spec
const (
	// AMD PCI vendor ID
	amdPCIVendorID = 0x1022

	// ASP mailbox register offsets (C2PMSG registers)
	// See drivers/crypto/ccp/sp-pci.c:sevv2
	aspRegCmdResp   = 0x10980 // C2PMSG_32: command/response register
	aspRegCmdBuffLo = 0x109e0 // C2PMSG_56: command buffer address (low 32 bits)
	aspRegCmdBuffHi = 0x109e4 // C2PMSG_57: command buffer address (high 32 bits)

	// ASP command/response register layout
	// bits [26:16] = command ID
	// bit  [31]    = response ready (ASP_CMDRESP_RESP)
	// bits [15:0]  = status (ASP_CMDRESP_STS)
	aspCmdRespCmdShift = 16
	aspCmdRespRespBit  = 1 << 31
	aspCmdRespStsMask  = 0xFFFF

	// SEV commands
	sevCmdGetID = 0x00C // SEV_CMD_GET_ID (AMD SEV API spec, Section 5.6)

	// ASP communication timeout
	aspTimeout = 5 * time.Second
)

// Supported AMD ASP device IDs (from drivers/crypto/ccp/sp-pci.c)
var aspDeviceIDs = map[uint16]bool{
	0x1456: true, // Family 17h?
	0x1486: true, // Milan
	0x14CA: true, // Genoa
	0x156E: true, // Turin
	0x15DF: true, // Raven Ridge?
	0x1649: true, // Family 19h?
	0x17D8: true, // Turin
}

// aspDevice represents an AMD ASP PCIe device
type aspDevice struct {
	// PCI location (e.g., "0000:21:00.2")
	location string
	// MMIO base address from BAR2
	mmioBase uint64
	// MMIO size
	mmioSize uint64
}

// aspMMIO provides access to ASP MMIO registers
type aspMMIO struct {
	dev  *os.File
	mmap mmap.MMap
}

// findASPDevices scans for AMD SP devices on the PCI bus
func findASPDevices() ([]aspDevice, error) {
	const pciDevicesPath = "/sys/bus/pci/devices"

	entries, err := os.ReadDir(pciDevicesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read PCI devices: %w", err)
	}

	var devices []aspDevice

	for _, entry := range entries {
		devicePath := filepath.Join(pciDevicesPath, entry.Name())

		// Read vendor ID
		vendorBytes, err := os.ReadFile(filepath.Join(devicePath, "vendor"))
		if err != nil {
			continue
		}
		vendorStr := strings.TrimSpace(string(vendorBytes))
		vendor, err := parseHexUint16(vendorStr)
		if err != nil || vendor != amdPCIVendorID {
			continue
		}

		// Read device ID
		deviceBytes, err := os.ReadFile(filepath.Join(devicePath, "device"))
		if err != nil {
			continue
		}
		deviceStr := strings.TrimSpace(string(deviceBytes))
		deviceID, err := parseHexUint16(deviceStr)
		if err != nil {
			continue
		}

		if !aspDeviceIDs[deviceID] {
			continue
		}

		// Read BAR2 (ASP MMIO BAR)
		// Resource files are at /sys/bus/pci/devices/<dev>/resource
		// Format: start end flags for each BAR
		resourceBytes, err := os.ReadFile(filepath.Join(devicePath, "resource"))
		if err != nil {
			continue
		}

		// Parse resource file - BAR2 is the 3rd line (index 2)
		resources := strings.Split(string(resourceBytes), "\n")
		if len(resources) < 3 {
			continue
		}

		bar2Fields := strings.Fields(resources[2])
		if len(bar2Fields) < 3 {
			continue
		}

		bar2Start, err := parseHexUint64(bar2Fields[0])
		if err != nil {
			continue
		}
		bar2End, err := parseHexUint64(bar2Fields[1])
		if err != nil {
			continue
		}

		bar2Size := bar2End - bar2Start + 1
		if bar2Size == 0 {
			continue
		}

		devices = append(devices, aspDevice{
			location: entry.Name(),
			mmioBase: bar2Start,
			mmioSize: bar2Size,
		})
	}

	return devices, nil
}

// parseHexUint16 parses a hex string like "0x1022" into a uint16
func parseHexUint16(s string) (uint16, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	v, err := strconv.ParseUint(s, 16, 16)
	return uint16(v), err
}

// parseHexUint64 parses a hex string like "0x00000000e0900000" into a uint64
func parseHexUint64(s string) (uint64, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	return strconv.ParseUint(s, 16, 64)
}

// openASPMMIO maps the ASP MMIO region via /dev/mem
func openASPMMIO(mmioBase, mmioSize uint64) (*aspMMIO, error) {
	dev, err := os.OpenFile("/dev/mem", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/mem: %w", err)
	}

	// Map the MMIO region
	// We need to align to page boundary
	const pageSize = 4096
	offset := mmioBase % pageSize
	mapBase := mmioBase - offset
	mapSize := mmioSize + offset

	// Check for overflow when converting to int
	// Max int is (1<<63)-1 on 64-bit systems
	const maxInt = uint64(1<<63 - 1)
	if mapSize > maxInt {
		dev.Close()
		return nil, fmt.Errorf("MMIO size too large: %d", mapSize)
	}
	if mapBase > maxInt {
		dev.Close()
		return nil, fmt.Errorf("MMIO base too large: %d", mapBase)
	}

	mmap, err := mmap.MapRegion(dev, int(mapSize), mmap.RDWR, 0, int64(mapBase))
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("failed to mmap ASP MMIO: %w", err)
	}

	return &aspMMIO{
		dev:  dev,
		mmap: mmap,
	}, nil
}

// close releases the MMIO mapping
func (p *aspMMIO) close() error {
	var errs []error
	if p.mmap != nil {
		if err := p.mmap.Unmap(); err != nil {
			errs = append(errs, err)
		}
	}
	if p.dev != nil {
		if err := p.dev.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// read32 reads a 32-bit value from the MMIO region
func (p *aspMMIO) read32(offset uint64) uint32 {
	return binary.LittleEndian.Uint32(p.mmap[offset:])
}

// write32 writes a 32-bit value to the MMIO region
func (p *aspMMIO) write32(offset uint64, value uint32) {
	binary.LittleEndian.PutUint32(p.mmap[offset:], value)
}

// pollCmd polls the ASP command/response register until response is ready
func (p *aspMMIO) pollCmd(timeout time.Duration) (uint32, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		reg := p.read32(aspRegCmdResp)
		if reg&aspCmdRespRespBit != 0 {
			status := reg & aspCmdRespStsMask
			if status != 0 {
				return status, fmt.Errorf("ASP command failed with status 0x%x", status)
			}
			return 0, nil
		}
		time.Sleep(100 * time.Microsecond)
	}
	return 0, fmt.Errorf("ASP command timeout")
}

// readSEVChipIDDirect attempts to get the chip ID via direct ASP mailbox access over PCI
func readSEVChipIDDirect() (*Result, error) {
	// Find ASP devices
	devices, err := findASPDevices()
	if err != nil {
		return nil, fmt.Errorf("failed to find ASP devices: %w", err)
	}
	if len(devices) == 0 {
		return nil, errors.New("no AMD SP device found")
	}

	// Try each device
	var lastErr error
	for _, dev := range devices {
		result, err := getChipIDFromDevice(dev)
		if err == nil {
			return result, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("failed to get chip ID from any ASP device: %w", lastErr)
}

// getChipIDFromDevice gets the chip ID from a specific ASP device
func getChipIDFromDevice(dev aspDevice) (*Result, error) {
	// Open ASP MMIO
	asp, err := openASPMMIO(dev.mmioBase, dev.mmioSize)
	if err != nil {
		return nil, err
	}
	defer asp.close()

	// Allocate DMA buffer for chip ID
	// The ASP needs a physical address it can DMA to, so we mlock the
	// buffer to try and avoid it getting swapped out or moved around.
	chipIDBuf := make([]byte, amdChipIDSize)
	if err := unix.Mlock(chipIDBuf); err != nil {
		return nil, fmt.Errorf("failed to lock Chip ID buffer in memory: %w", err)
	}
	defer unix.Munlock(chipIDBuf)

	// Get physical address of the buffer
	// This requires reading /proc/self/pagemap
	physAddr, err := getPhysicalAddress(chipIDBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to get physical address: %w", err)
	}

	// Allocate command buffer
	cmdBuf := make([]byte, 16) // sizeof(sev_data_get_id)
	cmdPhysAddr, err := getPhysicalAddress(cmdBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to get command buffer physical address: %w", err)
	}

	// Prepare the command structure
	// struct sev_data_get_id {
	//     uint64 address;  // physical address of output buffer
	//     uint32 len;      // length of buffer (in/out)
	//     uint32 pad;
	// }
	binary.LittleEndian.PutUint64(cmdBuf[0:8], physAddr)
	binary.LittleEndian.PutUint32(cmdBuf[8:12], amdChipIDSize)
	binary.LittleEndian.PutUint32(cmdBuf[12:16], 0)

	// Write command buffer address to ASP mailbox registers
	asp.write32(aspRegCmdBuffLo, uint32(cmdPhysAddr&0xFFFFFFFF))
	asp.write32(aspRegCmdBuffHi, uint32(cmdPhysAddr>>32))

	// Issue SEV_CMD_GET_ID command
	// Command ID goes in bits [26:16]
	cmdReg := uint32(sevCmdGetID << aspCmdRespCmdShift)
	asp.write32(aspRegCmdResp, cmdReg)

	// Poll for completion
	status, err := asp.pollCmd(aspTimeout)
	if err != nil {
		return nil, fmt.Errorf("ASP GET_ID command failed: %w (status 0x%x)", err, status)
	}

	// Read the returned length
	idLen := binary.LittleEndian.Uint32(cmdBuf[8:12])
	if idLen == 0 || idLen > amdChipIDSize {
		return nil, fmt.Errorf("invalid chip ID length: %d", idLen)
	}

	// Extract the chip ID
	chipID := make([]byte, idLen)
	copy(chipID, chipIDBuf[:idLen])

	return &Result{
		Vendor: VendorAMDSEVSNP,
		ID:     chipID,
	}, nil
}

// getPhysicalAddress returns the physical address of a byte slice
// This requires root privileges and /proc/self/pagemap access
func getPhysicalAddress(buf []byte) (uint64, error) {
	if len(buf) == 0 {
		return 0, errors.New("empty buffer")
	}

	// Get the virtual address of the buffer
	// We need to lock the memory to prevent it from being swapped
	// and to ensure the pages stay resident

	// Open pagemap
	pagemap, err := os.Open("/proc/self/pagemap")
	if err != nil {
		return 0, fmt.Errorf("failed to open /proc/self/pagemap: %w (need root?)", err)
	}
	defer pagemap.Close()

	// Get the virtual address
	// This is tricky in Go - we need to use reflection or unsafe
	// For now, we'll use a simpler approach with /proc/self/maps and assume
	// we can get the physical address via pagemap

	// Calculate page index
	// Page size is typically 4KB
	const pageSize = 4096

	// We need the virtual address. In Go, we can get it via:
	// - Using unsafe.Pointer and reflect.SliceHeader
	// - Or using syscall and parsing /proc/self/maps

	// For simplicity and because this is a privileged operation anyway,
	// let's use a C helper or implement the full pagemap parsing

	// Actually, let's implement a simpler version that works for our use case
	// We'll read the pagemap entry for the buffer's address

	// Get virtual address using a helper
	vaddr := getSliceAddress(buf)

	// Calculate page frame number index
	pfnIndex := (vaddr / pageSize) * 8 // 8 bytes per entry

	// Check for overflow - max int64 is (1<<63)-1
	const maxInt64 = uint64(1<<63 - 1)
	if pfnIndex > maxInt64 {
		return 0, fmt.Errorf("page index too large: %d", pfnIndex)
	}

	// Seek to the pagemap entry
	_, err = pagemap.Seek(int64(pfnIndex), 0)
	if err != nil {
		return 0, fmt.Errorf("failed to seek pagemap: %w", err)
	}

	// Read the pagemap entry (8 bytes)
	entry := make([]byte, 8)
	_, err = pagemap.Read(entry)
	if err != nil {
		return 0, fmt.Errorf("failed to read pagemap: %w", err)
	}

	pfn := binary.LittleEndian.Uint64(entry)

	// Check if page is present
	if pfn&(1<<63) == 0 {
		return 0, errors.New("page not present")
	}

	// Extract page frame number (bits 0-54)
	pageFrame := pfn & ((1 << 55) - 1)

	// Calculate physical address
	physAddr := (pageFrame * pageSize) + (vaddr % pageSize)

	return physAddr, nil
}

// getSliceAddress returns the virtual address of a byte slice's data
func getSliceAddress(buf []byte) uint64 {
	// Use the slice's data pointer via unsafe
	// This is safe because we're just reading the address for pagemap lookup
	if len(buf) == 0 {
		return 0
	}
	return uint64(uintptr(unsafe.Pointer(&buf[0])))
}
