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
	"crypto"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
)

// Signer implements crypto.Signer for TPM keys.
type Signer struct {
	publicKey   crypto.PublicKey
	TpmPath     string
	PublicBlob  []byte
	PrivateBlob []byte
	PCRS        []uint
	handle      tpm2.TPMHandle
	KeyAlg      tpm2.TPMAlgID
}

// Load loads signing key into tpm.
func (s *Signer) Load(tpm *TPM) (tpm2.TPMHandle, error) {
	if s.handle != tpm2.TPMHandle(0) {
		return s.handle, nil
	}

	handle, err := tpm.LoadKey(tpm.srkHandle, s.PublicBlob, s.PrivateBlob)
	if err != nil {
		return 0, fmt.Errorf("failed to load key: %w", err)
	}
	s.handle = handle
	return handle, nil
}

// Unload unloads signing key from tpm
func (s *Signer) Unload(tpm *TPM) error {
	if s.handle == tpm2.TPMHandle(0) {
		return nil
	}
	return tpm.UnloadKey(s.handle)
}

// Public returns the public key of the signer.
func (s *Signer) Public() crypto.PublicKey {
	if s.publicKey != nil {
		return s.publicKey
	}
	tpm, err := OpenTPM(s.TpmPath)
	if err != nil {
		return nil
	}
	defer tpm.Close()

	handle, err := s.Load(tpm)
	if err != nil {
		return nil
	}
	defer func() {
		// errors are ignored as the interface assumes it's safe to read public key
		// but, errors of loading/unloading keys should be tracked (T186064094).
		_ = s.Unload(tpm)
	}()

	key, _ := tpm.ReadPublicKey(handle)
	s.publicKey = key

	return key
}

// Sign performs a TPM sign operation on digest and returns the signature.
// NOTE: `rand` is ignored as the TPM is the source of randomness.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if opts != nil && opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("unsupported hash function: %v", opts.HashFunc())
	}

	// sha256 digest must be 32 bytes
	if len(digest) != 32 {
		return nil, fmt.Errorf("digest must be 32 bytes, got %d", len(digest))
	}

	tpm, err := OpenTPM(s.TpmPath)
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	handle, err := tpm.LoadKey(tpm.srkHandle, s.PublicBlob, s.PrivateBlob)
	if err != nil {
		return nil, fmt.Errorf("failed to load key: %w", err)
	}
	defer func() {
		unloadErr := tpm.UnloadKey(handle)
		if err == nil {
			err = unloadErr
		}
	}()

	var signAlg tpm2.TPMAlgID
	switch s.KeyAlg {
	case tpm2.TPMAlgRSA:
		signAlg = tpm2.TPMAlgRSASSA
	case tpm2.TPMAlgECC:
		signAlg = tpm2.TPMAlgECDSA
	default:
		return nil, fmt.Errorf("unsupported algorithm: %v", s.KeyAlg)
	}

	if len(s.PCRS) > 0 {
		signature, err = tpm.SignWithPolicy(handle, signAlg, digest, s.PCRS)
	} else {
		signature, err = tpm.Sign(handle, signAlg, digest)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to perform tpm sign: %w", err)
	}
	return signature, nil
}

// GenerateSigningKey generates a signing key on the TPM, and returns wrapped public and private key parts.
func GenerateSigningKey(tpm *TPM, alg tpm2.TPMAlgID) (public []byte, private []byte, err error) {
	var (
		keyTemplate tpm2.TPMTPublic
	)
	switch alg {
	case tpm2.TPMAlgRSA:
		keyTemplate = GetRSASigningKeyTemplate()
	case tpm2.TPMAlgECC:
		keyTemplate = GetECCSigningKeyTemplate()
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm: %v", alg)
	}

	public, private, _, _, _, err = tpm.CreateKey(
		tpm.srkHandle,
		"", // Object's authValue (password).
		keyTemplate,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create key: %w", err)
	}
	return public, private, nil
}

// GenerateSigningKeyWithPolicy generates a signing key on the TPM using the
// specified PCR policy and returns the wrapped public and private key parts.
// The alg parameter specifies the key algorithm (TPMAlgRSA or TPMAlgECC), and
// the pcrs parameter defines the PCR indices that must be satisfied to use the key
func GenerateSigningKeyWithPolicy(tpm *TPM, alg tpm2.TPMAlgID, pcrs ...uint) (public []byte, private []byte, err error) {
	var keyTemplate tpm2.TPMTPublic

	pcrSelection, err := tpm.SelectPCRs(pcrs...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to select PCRs: %w", err)
	}

	session, sessionCloser, err := tpm.NewSession()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create policy session: %w", err)
	}
	defer sessionCloser()

	authPolicy, err := tpm.PCRPolicy(session.Handle(), pcrSelection)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create PCR policy: %w", err)
	}

	switch alg {
	case tpm2.TPMAlgRSA:
		keyTemplate = GetRSASigningKeyTemplateWithPolicy(authPolicy)
	case tpm2.TPMAlgECC:
		keyTemplate = GetECCSigningKeyTemplateWithPolicy(authPolicy)
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm: %v", alg)
	}

	public, private, _, _, _, err = tpm.CreateKey(
		tpm.srkHandle,
		"", // Object's authValue (password).
		keyTemplate,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create key: %w", err)
	}
	return public, private, nil
}
