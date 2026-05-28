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
	"encoding/binary"
	"fmt"
	"os"
	"reflect"
	"runtime"

	"golang.org/x/sys/unix"
)

const (
	sevGetID2         = 8
	getID2Size        = 12
	sevIssueCmdSize   = 16
	sevIssueCmdErrOff = 12

	iocNRBits   = 8
	iocTypeBits = 8
	iocSizeBits = 14

	iocNRShift   = 0
	iocTypeShift = iocNRShift + iocNRBits
	iocSizeShift = iocTypeShift + iocTypeBits
	iocDirShift  = iocSizeShift + iocSizeBits

	iocWrite = 1
	iocRead  = 2
)

var sevIssueCmdIOCTL = ioc(iocRead|iocWrite, 'S', 0, sevIssueCmdSize)

func ioc(dir, typ, nr, size uintptr) uintptr {
	return (dir << iocDirShift) |
		(typ << iocTypeShift) |
		(nr << iocNRShift) |
		(size << iocSizeShift)
}

func byteSlicePtr(b []byte) uintptr {
	return reflect.ValueOf(b).Pointer()
}

func readSEVChipID() ([]byte, error) {
	device, err := os.OpenFile("/dev/sev", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer device.Close()

	chipID := make([]byte, amdChipIDSize)
	getID2 := make([]byte, getID2Size)
	binary.LittleEndian.PutUint64(getID2[0:8], uint64(byteSlicePtr(chipID)))
	binary.LittleEndian.PutUint32(getID2[8:12], uint32(amdChipIDSize))

	cmd := make([]byte, sevIssueCmdSize)
	binary.LittleEndian.PutUint32(cmd[0:4], sevGetID2)
	binary.LittleEndian.PutUint64(cmd[4:12], uint64(byteSlicePtr(getID2)))

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		device.Fd(),
		sevIssueCmdIOCTL,
		byteSlicePtr(cmd),
	)

	// Make sure all of thes objects don't get freed until after we do the
	// ioctl.
	runtime.KeepAlive(chipID)
	runtime.KeepAlive(getID2)
	runtime.KeepAlive(cmd)
	runtime.KeepAlive(device)

	sevError := binary.LittleEndian.Uint32(cmd[sevIssueCmdErrOff:])
	if errno != 0 {
		if sevError != 0 {
			return nil, fmt.Errorf("SEV_GET_ID2 ioctl: %w (SEV firmware error %d)", errno, sevError)
		}
		return nil, fmt.Errorf("SEV_GET_ID2 ioctl: %w", errno)
	}
	if sevError != 0 {
		return nil, fmt.Errorf("SEV_GET_ID2 ioctl returned SEV firmware error %d", sevError)
	}
	length := binary.LittleEndian.Uint32(getID2[8:12])
	if length == 0 || length > amdChipIDSize {
		return nil, fmt.Errorf("SEV_GET_ID2 returned invalid ChipID length %d", length)
	}

	return chipID[:length], nil
}
