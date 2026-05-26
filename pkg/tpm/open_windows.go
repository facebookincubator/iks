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
	"os"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// OpenTPM opens the Windows TPM as a TPM2.0 device and returns a handle to it.
// Note: the argument is ignored.
func OpenTPM(_ string) (*TPM, error) {
	return OpenTPMWithSRKHandle("", SRKECCHandle)
}

// OpenTPMWithSRKHandle opens Windows TPM as a TPM2.0 device and returns a handle to it.
// h is a handle to use in TPM operations.
// Note: the first argument is ignored.
func OpenTPMWithSRKHandle(_ string, h tpm2.TPMHandle) (*TPM, error) {
	tpm, err := tpmutil.OpenTPM()
	if errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if err != nil {
		return nil, fmt.Errorf("could not open err: %w", err)
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
