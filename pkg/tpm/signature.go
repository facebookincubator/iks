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
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
)

func validateSignAlg(alg tpm2.TPMAlgID) error {
	switch alg {
	case tpm2.TPMAlgRSASSA, tpm2.TPMAlgECDSA:
		return nil
	default:
		return fmt.Errorf("unsupported signing algorithm: %v", alg)
	}
}

// GetSignature returns the signature bytes from a TPMTSignature
func GetSignature(signature tpm2.TPMTSignature) ([]byte, error) {
	switch signature.SigAlg {
	case tpm2.TPMAlgRSASSA:
		rsassa, err := signature.Signature.RSASSA()
		if err != nil {
			return nil, fmt.Errorf("failed to get RSASSA signature: %w", err)
		}
		return rsassa.Sig.Buffer, nil
	case tpm2.TPMAlgECDSA:
		ecdsa, err := signature.Signature.ECDSA()
		if err != nil {
			return nil, fmt.Errorf("failed to get ECDSA signature: %w", err)
		}
		return asn1.Marshal(struct {
			R, S *big.Int
		}{
			R: new(big.Int).SetBytes(ecdsa.SignatureR.Buffer),
			S: new(big.Int).SetBytes(ecdsa.SignatureS.Buffer),
		})
	default:
		return nil, fmt.Errorf("unsupported signing algorithm: %v", signature.SigAlg)
	}
}

// GetTPMSignature constructs a TPMTSignature struct from signature bytes, only supports RSASSA and ECDSA
func GetTPMSignature(signature []byte, alg tpm2.TPMAlgID) (*tpm2.TPMTSignature, error) {
	switch alg {
	case tpm2.TPMAlgRSASSA:
		return &tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgRSASSA,
			Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgRSASSA, &tpm2.TPMSSignatureRSA{
				Hash: tpm2.TPMAlgSHA256,
				Sig: tpm2.TPM2BPublicKeyRSA{
					Buffer: signature,
				},
			}),
		}, nil
	case tpm2.TPMAlgECDSA:
		var points struct {
			R, S *big.Int
		}
		_, err := asn1.Unmarshal(signature, &points)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal ECDSA signature: %w", err)
		}
		return &tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgECDSA,
			Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
				Hash: tpm2.TPMAlgSHA256,
				SignatureR: tpm2.TPM2BECCParameter{
					Buffer: points.R.Bytes(),
				},
				SignatureS: tpm2.TPM2BECCParameter{
					Buffer: points.S.Bytes(),
				},
			}),
		}, nil
	}
	return nil, fmt.Errorf("unsupported signing algorithm: %v", alg)
}
