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
	"crypto"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

// pcrAlg maps a PCR digest width to the hash algorithm of the bank the digest was read from.
// Every bank has a distinct digest width, so the width alone identifies the bank.
func pcrAlg(digestLen int) (tpm2.TPMIAlgHash, error) {
	switch digestLen {
	case crypto.SHA256.Size():
		return tpm2.TPMAlgSHA256, nil
	case crypto.SHA384.Size():
		return tpm2.TPMAlgSHA384, nil
	case crypto.SHA512.Size():
		return tpm2.TPMAlgSHA512, nil
	default:
		return 0, fmt.Errorf("%d byte digest matches no known PCR bank", digestLen)
	}
}

// pcrBankAlg infers which PCR bank the attested state was read from. The bank is not carried
// alongside the attested values, but each bank has a distinct digest width. It has to be named
// correctly in the selection: the selection is marshalled into the policy digest, so claiming a
// bank the values did not come from yields a digest the attester's TPM never computed.
// The first selected PCR sets the bank, and every other selected PCR has to agree with it.
func pcrBankAlg(selectedPCRs []uint, pcrDigestByIndex map[uint][]byte) (tpm2.TPMIAlgHash, error) {
	if len(selectedPCRs) == 0 {
		return 0, errors.New("policy selects no PCRs")
	}

	firstPCR := selectedPCRs[0]
	firstDigest, ok := pcrDigestByIndex[firstPCR]
	if !ok {
		return 0, fmt.Errorf("PCR index %d not found in state", firstPCR)
	}

	bankAlg, err := pcrAlg(len(firstDigest))
	if err != nil {
		return 0, fmt.Errorf("PCR index %d: %w", firstPCR, err)
	}

	for _, idx := range selectedPCRs[1:] {
		digest, ok := pcrDigestByIndex[idx]
		if !ok {
			return 0, fmt.Errorf("PCR index %d not found in state", idx)
		}

		alg, err := pcrAlg(len(digest))
		if err != nil {
			return 0, fmt.Errorf("PCR index %d: %w", idx, err)
		}

		if alg != bankAlg {
			return 0, fmt.Errorf(
				"PCR index %d is from bank 0x%04x, but PCR index %d is from bank 0x%04x",
				idx, uint16(alg), firstPCR, uint16(bankAlg),
			)
		}
	}

	return bankAlg, nil
}

// computePolicyDigestFromPCRs computes the expected auth policy digest from PCR values.
// We use PolicyPCR to compute policy digest.
func computePolicyDigestFromPCRs(expectedPCRPolicy PolicyPCRs, pcrsState []PCR, sessionAlg tpm2.TPMIAlgHash) ([]byte, error) {
	// We use policy calculator to calculate policy digest without a TPM
	policyCalc, err := tpm2.NewPolicyCalculator(sessionAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to create policy calculator for session alg 0x%04x: %w", uint16(sessionAlg), err)
	}

	pcrDigestByIndex := make(map[uint][]byte, len(pcrsState))
	for _, pcr := range pcrsState {
		pcrDigestByIndex[pcr.Index] = pcr.Digest
	}

	bankAlg, err := pcrBankAlg(expectedPCRPolicy.PCRs, pcrDigestByIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to determine PCR bank from attested state: %w", err)
	}

	// This part is used for get tpm2.TPMLPCRSelection
	// Basically the PCR to include in the check digest
	pcrSelection := tpm2.TPMSPCRSelection{
		Hash:      bankAlg,
		PCRSelect: tpm2.PCClientCompatible.PCRs(expectedPCRPolicy.PCRs...),
	}

	pcrSelectionList := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{pcrSelection},
	}

	// This is algorithm to calculate PCR Digest
	// PCR_Digest = Hash(PCRa || PCRb || PCRc || ... || PCRn)
	// Please refer to Part 3, Commands, section 23.7.2
	sessionHash, err := sessionAlg.Hash()
	if err != nil {
		return nil, fmt.Errorf("unsupported policy session hash algorithm 0x%04x: %w", uint16(sessionAlg), err)
	}

	hash := sessionHash.New()
	for _, idx := range expectedPCRPolicy.PCRs {
		digest, ok := pcrDigestByIndex[idx]
		if !ok {
			return nil, fmt.Errorf("PCR index %d not found in state", idx)
		}
		hash.Write(digest)
	}
	pcrDigest := hash.Sum(nil)

	// We use trial policy for policy computation via PolicyCalculator
	// We use that because we can't do policyDigest computation in the attester TPM (Cattestation doesn't have access to attester TPM)
	// Please refer to Part 1, Architecture, section 19.7.10
	policyPCR := tpm2.PolicyPCR{
		PolicySession: tpm2.TPMHandle(tpm2.TPMSETrial), // Trial session type, please refer to Part 2, Structures, section 6.11
		Pcrs:          pcrSelectionList,
		PcrDigest: tpm2.TPM2BDigest{
			Buffer: pcrDigest,
		},
	}

	// We calculate policy digest using policy PCR update
	// This function basically do
	// Hash(TPM_CC_Policy_PCR || PCR Selection || PCR Digest)
	// Please refer to Part 1, Architecture, Annex A.2
	if err := policyPCR.Update(policyCalc); err != nil {
		return nil, fmt.Errorf("failed to update policy calculator: %w", err)
	}

	digest := policyCalc.Hash().Digest
	return digest, nil
}

// VerifyPolicy verifies the policy digest of the attestation certificate
// by comparing Policy Digest in the public key with the computed Policy Digest synthetically without access to attester TPM .
// It takes the public key bytes as a parameter to allow external callers to use this function.
func VerifyPolicyDigest(public []byte, expectedPCRPolicy PolicyPCRs, pcrsState []PCR) error {
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](public)
	if err != nil {
		return fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	// The policy session hash has to be the object's nameAlg, otherwise the TPM would not have
	// accepted the resulting digest as this object's auth policy in the first place.
	// Please refer to Part 1, Architecture, section 27.2
	expectedPolicyDigest, err := computePolicyDigestFromPCRs(expectedPCRPolicy, pcrsState, pub.NameAlg)
	if err != nil {
		return fmt.Errorf("failed to compute auth policy: %w", err)
	}

	if !bytes.Equal(pub.AuthPolicy.Buffer, expectedPolicyDigest) {
		return fmt.Errorf("auth policy mismatch: expected %x, got %x", expectedPolicyDigest, pub.AuthPolicy.Buffer)
	}

	return nil
}
