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
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

// computePolicyDigestFromPCRs computes the expected auth policy digest from PCR values.
// We use PolicyPCR to compute policy digest.
func computePolicyDigestFromPCRs(expectedPCRPolicy PolicyPCRs, pcrsState []PCR) ([]byte, error) {
	// We use policy calculator to calculate policy digest without a TPM
	policyCalc, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to create policy calculator: %w", err)
	}

	// This part is used for get tpm2.TPMLPCRSelection
	// Basically the PCR to include in the check digest
	pcrSelection := tpm2.TPMSPCRSelection{
		Hash:      tpm2.TPMAlgSHA256,
		PCRSelect: tpm2.PCClientCompatible.PCRs(expectedPCRPolicy.PCRs...),
	}

	pcrSelectionList := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{pcrSelection},
	}

	// This is algorithm to calculate PCR Digest
	// PCR_Digest = Hash(PCRa || PCRb || PCRc || ... || PCRn)
	// Please refer to Part 3, Commands, section 23.7.2
	pcrDigestByIndex := make(map[uint][]byte, len(pcrsState))
	for _, pcr := range pcrsState {
		pcrDigestByIndex[pcr.Index] = pcr.Digest
	}

	hash := crypto.SHA256.New()
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

	expectedPolicyDigest, err := computePolicyDigestFromPCRs(expectedPCRPolicy, pcrsState)
	if err != nil {
		return fmt.Errorf("failed to compute auth policy: %w", err)
	}

	if !bytes.Equal(pub.AuthPolicy.Buffer, expectedPolicyDigest) {
		return fmt.Errorf("auth policy mismatch: expected %x, got %x", expectedPolicyDigest, pub.AuthPolicy.Buffer)
	}

	return nil
}
