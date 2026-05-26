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
	"syscall"

	"github.com/google/go-tpm/tpm2"
)

// ErrorType is the type of a TPM error.
type ErrorType string

const (
	// MissingDeviceErrType means Linux did not create /dev/tpm0
	MissingDeviceErrType ErrorType = "TPM_DEVICE_FILE_MISSING"
	// ResourceBusyErrType is a system error.
	ResourceBusyErrType = "TPM_RESOURCE_BUSY"
	// SealMismatchErrType is a TPM seal/unseal mismatch error.
	SealMismatchErrType = "TPM_SEAL_MISMATCH"
	// TimeoutErrType is a timeout error.
	TimeoutErrType = "TPM_TIMEOUT"
	// TPMOpenErrType is a TPM open error.
	TPMOpenErrType = "TPM_OPEN_ERROR"
	// TPMNotProvisionedErrType is a TPM not provisioned error.
	TPMNotProvisionedErrType = "TPM_NOT_PROVISIONED"
	// TPMShutdown indicates the TPM appears to have entered shutdown mode.
	TPMShutdown = "TPM_IN_SHUTDOWN"
	// TPMNeedsFirmware indicates the TPM is in its bootloader and needs a
	// firmware image.
	TPMNeedsFirmware = "TPM_NEEDS_FIRMWARE"
	// OtherErrType is an error type for unknown/other/uncategorized errors.
	OtherErrType = "OTHER_ERROR"
)

// Error is a TPM related error, with a categorized error type.
type Error struct {
	Err  error
	Type ErrorType
}

var _ error = (*Error)(nil)

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %v", e.Type, e.Err)
}

// Unwrap returns the underlying error.
func (e *Error) Unwrap() error {
	return e.Err
}

// Is checks if the error is the same as the target error.
func (e *Error) Is(target error) bool {
	return errors.Is(e.Err, target)
}

// As checks if the error is assignable to the type passed in.
func (e *Error) As(target any) bool {
	return errors.As(e.Err, target)
}

// CategorizedError categorizes the error and returns the error type.
func CategorizedError(err error) *Error {
	if err == nil {
		return nil
	}
	tpmErr := &Error{}
	if errors.As(err, &tpmErr) {
		return tpmErr
	}

	var (
		errType    ErrorType
		tpmRCErr   tpm2.TPMRC
		syscallErr syscall.Errno
	)
	switch {
	case errors.As(err, &tpmRCErr):
		// catch errors returned from successful communications with the TPM
		return &Error{
			Err:  err,
			Type: ToErrorType(tpmRCErr),
		}
	case errors.As(err, &syscallErr):
		// catch errors returned from failed communications with the TPM, mostly system related
		switch syscallErr {
		case syscall.EBUSY:
			errType = ResourceBusyErrType
		case syscall.ETIMEDOUT, syscall.ETIME, syscall.EAGAIN:
			errType = TimeoutErrType
		}
		return &Error{
			Err:  syscallErr,
			Type: errType,
		}
	default:
		// return generic/other/unknown error
		// mostly related to bad formatted commands, failures to parse command results, etc
		return &Error{
			Err:  err,
			Type: OtherErrType,
		}
	}
}
