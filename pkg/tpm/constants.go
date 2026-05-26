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
	"github.com/google/go-tpm/tpm2"
)

const (
	// SRKRSAHandle is the TPM handle for the RSA Storage Root Key
	SRKRSAHandle = tpm2.TPMHandle(0x81000001)
	// SRKECCHandle is the TPM handle for the ECC Storage Root Key
	SRKECCHandle = tpm2.TPMHandle(0x81000002)
	// EKRSAHandle is the TPM handle for the RSA Endorsement Key
	EKRSAHandle = tpm2.TPMHandle(0x81010001)
	// EKECCHandle is the TPM handle for the ECC Endorsement Key
	EKECCHandle = tpm2.TPMHandle(0x81010002)
	// EKRSACERTNVIndex is the TPM handle for the RSA Endorsement Key Certificate
	// See TCG EK Credential Profile 2.6, section 2.2.2.4
	EKRSACERTNVIndex = tpm2.TPMHandle(0x1c00002)
	// EKRSACERT2048NVIndex is the TPM handle for the RSA Endorsement Key Certificate with 2048 key size
	// See TCG EK Credential Profile 2.0, section 2.2.2.4
	EKRSACERT2048NVIndex = tpm2.TPMHandle(0x1c00012)
	// EKECCCERTNVIndex is the TPM handle for the ECC Endorsement Key Certificate
	// See TCG EK Credential Profile 2.6, section 2.2.2.4
	EKECCCERTNVIndex = tpm2.TPMHandle(0x1c0000a)
	// EKECCCERT384NVIndex is the TPM handle for the ECC Endorsement Key Certificate with P384 curve
	// See TCG EK Credential Profile 2.0, section 2.2.2.4
	EKECCCERT384NVIndex = tpm2.TPMHandle(0x01c00016)
)

// GetRSASigningKeyTemplate returns the key template for the RSA signing key.
func GetRSASigningKeyTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
			Scheme: tpm2.TPMTRSAScheme{
				Scheme: tpm2.TPMAlgRSASSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSASSA, &tpm2.TPMSSigSchemeRSASSA{
					HashAlg: tpm2.TPMAlgSHA256,
				}),
			},
			KeyBits: tpm2.TPMKeyBits(2048),
		}),
	}
}

// GetECCSigningKeyTemplate returns the key template for the ECC signing key.
func GetECCSigningKeyTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			CurveID: tpm2.TPMECCNistP256,
			Scheme: tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{
					HashAlg: tpm2.TPMAlgSHA256,
				}),
			},
		}),
	}
}

// GetRSASigningKeyTemplateWithPolicy returns the key template for an RSA signing key
// with PCR policy enforcement. The authPolicy parameter defines the authorization policy
// digest that enforces the PCR policy specified by the policy parameter
func GetRSASigningKeyTemplateWithPolicy(authPolicy tpm2.TPM2BDigest) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			// We set UserWithAuth to false to enforce selected PCR policy only.
			// Please refer to tpm2 TPMAObject.UserWithAuth documentation for more details
			UserWithAuth: false,
			SignEncrypt:  true,
		},
		AuthPolicy: authPolicy,
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
			Scheme: tpm2.TPMTRSAScheme{
				Scheme: tpm2.TPMAlgRSASSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSASSA, &tpm2.TPMSSigSchemeRSASSA{
					HashAlg: tpm2.TPMAlgSHA256,
				}),
			},
			KeyBits: tpm2.TPMKeyBits(2048),
		}),
	}
}

// GetECCSigningKeyTemplateWithPolicy returns the key template for an ECC signing key
// with PCR policy enforcement. The authPolicy parameter defines the authorization policy
// digest that enforces the PCR policy specified by the policy parameter.
func GetECCSigningKeyTemplateWithPolicy(authPolicy tpm2.TPM2BDigest) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			// We set UserWithAuth to false to enforce selected PCR policy only.
			// Please refer to tpm2 TPMAObject.UserWithAuth documentation for more details
			UserWithAuth: false,
			SignEncrypt:  true,
		},
		AuthPolicy: authPolicy,
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			CurveID: tpm2.TPMECCNistP256,
			Scheme: tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{
					HashAlg: tpm2.TPMAlgSHA256,
				}),
			},
		}),
	}
}

// GetECCAttestationKeyTemplate returns the key template for an ECC Attestation Key.
func GetECCAttestationKeyTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
			// can't sign any data, only TPM structs.
			Restricted: true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			CurveID: tpm2.TPMECCNistP256,
			Scheme: tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{
					HashAlg: tpm2.TPMAlgSHA256,
				}),
			},
		}),
	}
}

// GetRSAAttestationKeyTemplate returns the key template for an RSA Attestation Key.
func GetRSAAttestationKeyTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
			// can't sign any data, only TPM structs.
			Restricted: true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
			Scheme: tpm2.TPMTRSAScheme{
				Scheme: tpm2.TPMAlgRSASSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSASSA, &tpm2.TPMSSigSchemeRSASSA{
					HashAlg: tpm2.TPMAlgSHA256,
				}),
			},
			KeyBits: tpm2.TPMKeyBits(2048),
		}),
	}
}

// GetECCEKP384Template returns the key template for an ECC P384 Storage (non-Firmware-limited) EK Template.
// see TCG Credentials Profile EK 2.0
//
//	https://trustedcomputinggroup.org/wp-content/uploads/TCG-EK-Credential-Profile-for-TPM-Family-2.0-Level-0-Version-2.7_Pub.pdf#page=51
func GetECCEKP384Template() tpm2.TPMTPublic {
	var PolicyBSHA384 = []byte{
		0xB2, 0x6E, 0x7D, 0x28, 0xD1, 0x1A, 0x50, 0xBC,
		0x53, 0xD8, 0x82, 0xBC, 0xF5, 0xFD, 0x3A, 0x1A,
		0x07, 0x41, 0x48, 0xBB, 0x35, 0xD3, 0xB4, 0xE4,
		0xCB, 0x1C, 0x0A, 0xD9, 0xBD, 0xE4, 0x19, 0xCA,
		0xCB, 0x47, 0xBA, 0x09, 0x69, 0x96, 0x46, 0x15,
		0x0F, 0x9F, 0xC0, 0x00, 0xF3, 0xF8, 0x0E, 0x12,
	}

	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA384,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			// one difference to note here against the regular low-range EK template is that
			// UserWithAuth is set to true. This makes the TPM expect an authValue (i.e. password) rather than auth Session (i.e. Policy)
			UserWithAuth:    true,
			AdminWithPolicy: true,
			Restricted:      true,
			Decrypt:         true,
		},
		AuthPolicy: tpm2.TPM2BDigest{
			Buffer: PolicyBSHA384,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(256),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgNull,
				},
				CurveID: tpm2.TPMECCNistP384,
				KDF: tpm2.TPMTKDFScheme{
					Scheme: tpm2.TPMAlgNull,
				},
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: []byte{}},
				Y: tpm2.TPM2BECCParameter{Buffer: []byte{}},
			},
		),
	}
}
