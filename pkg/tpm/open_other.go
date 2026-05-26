//go:build !windows

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
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// OpenTPM opens the provided tpmPath as a TPM2.0 device and returns a handle to it.
func OpenTPM(tpmPath string) (*TPM, error) {
	return OpenTPMWithSRKHandle(tpmPath, SRKECCHandle)
}

// OpenTPMFromRWC uses the provided ReadWriteCloser interface to talk to the TPM. It
// does not do any validation that the TPM is healthy.
func OpenTPMFromRWC(rwc io.ReadWriteCloser) (*TPM, error) {
	return &TPM{
		rwc:       rwc,
		srkHandle: SRKECCHandle,
	}, nil
}

// OpenTPMWithSRKHandle opens the provided tpmPath as a TPM2.0 device and returns a handle to it.
// h is a handle to use in TPM operations.
func OpenTPMWithSRKHandle(tpmPath string, h tpm2.TPMHandle) (*TPM, error) {
	tpm, err := tpmutil.OpenTPM(tpmPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if err != nil {
		return nil, fmt.Errorf("could not open tpm: %s, err: %w", tpmPath, err)
	}

	errChan := make(chan error, 1)
	go func() {
		// Do a basic sanity check to make sure we can talk to the TPM
		_, getErr := getProperty(tpm, tpm2.TPMPTManufacturer)
		errChan <- getErr
	}()

	select {
	case err = <-errChan:
		break
	case <-time.After(10 * time.Second):
		err = errors.New("timed out getting manufacturer")
	}

	if err != nil {
		tpm.Close()
		return nil, fmt.Errorf("could not talk to tpm: %w", err)
	}

	return &TPM{
		rwc:       tpm,
		srkHandle: h,
	}, nil
}
