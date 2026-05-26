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
	"crypto/x509"
	"fmt"

	attestHelper "github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Quote signs PCR values with a TPM key and returns the quote and signature.
func (tpm *TPM) Quote(signingHandle tpm2.TPMHandle, pcrs []uint, alg tpm2.TPMAlgID, data []byte) (quote []byte, signature []byte, err error) {
	if err := validateSignAlg(alg); err != nil {
		return nil, nil, fmt.Errorf("unsupported signing algorithm: %w", err)
	}

	pcrAlg, err := tpm.getPCRHashAlg()
	if err != nil {
		return nil, nil, fmt.Errorf("could not read TPM PCR algorithms: %w", err)
	}

	tpmTransport := transport.FromReadWriter(tpm.rwc)
	cmd := tpm2.Quote{
		SignHandle: tpm2.NamedHandle{
			Handle: signingHandle,
		},
		QualifyingData: tpm2.TPM2BData{
			Buffer: data,
		},
		PCRSelect: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      pcrAlg,
					PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs...),
				},
			},
		},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: alg,
			Details: tpm2.NewTPMUSigScheme(
				alg,
				&tpm2.TPMSSchemeHash{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
	}

	resp, err := cmd.Execute(tpmTransport)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to execute Quote command: %w", err)
	}

	quote = resp.Quoted.Bytes()
	signature, err = GetSignature(resp.Signature)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get signature: %w", err)
	}
	return
}

// CertifyCreation signs TPMSAttest struct - certifying info about handle's object creation - with signerHandle.
func (tpm *TPM) CertifyCreation(handle tpm2.TPMHandle, signerHandle tpm2.TPMHandle, alg tpm2.TPMAlgID, creationHash []byte, creationTicket tpm2.TPMTTKCreation) (attestation []byte, signature []byte, err error) {
	if err := validateSignAlg(alg); err != nil {
		return nil, nil, fmt.Errorf("unsupported signing algorithm: %w", err)
	}

	tpmTransport := transport.FromReadWriter(tpm.rwc)
	cmd := tpm2.CertifyCreation{
		SignHandle: tpm2.NamedHandle{
			Handle: signerHandle,
		},
		ObjectHandle: tpm2.NamedHandle{
			Handle: handle,
		},
		CreationHash: tpm2.TPM2BDigest{
			Buffer: creationHash,
		},
		CreationTicket: creationTicket,
		InScheme: tpm2.TPMTSigScheme{
			Scheme: alg,
			Details: tpm2.NewTPMUSigScheme(
				alg,
				&tpm2.TPMSSchemeHash{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
	}
	resp, err := cmd.Execute(tpmTransport)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to certify creation of handle %v with signerHandle %v: %w", handle, signerHandle, err)
	}

	attestation = resp.CertifyInfo.Bytes()
	signature, err = GetSignature(resp.Signature)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get signature: %w", err)
	}
	return
}

// Certify signs TPMSAttest struct - containing info about handle - with signerHandle.
func (tpm *TPM) Certify(handle tpm2.TPMHandle, signerHandle tpm2.TPMHandle, alg tpm2.TPMAlgID) (attestation []byte, signature []byte, err error) {
	if err := validateSignAlg(alg); err != nil {
		return nil, nil, fmt.Errorf("unsupported signing algorithm: %w", err)
	}

	tpmTransport := transport.FromReadWriter(tpm.rwc)
	cmd := tpm2.Certify{
		ObjectHandle: tpm2.NamedHandle{
			Handle: handle,
		},
		SignHandle: tpm2.NamedHandle{
			Handle: signerHandle,
		},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: alg,
			Details: tpm2.NewTPMUSigScheme(
				alg,
				&tpm2.TPMSSchemeHash{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
	}
	resp, err := cmd.Execute(tpmTransport)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to certify handle %v with signerHandle %v: %w", handle, signerHandle, err)
	}

	attestation = resp.CertifyInfo.Bytes()
	signature, err = GetSignature(resp.Signature)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get signature: %w", err)
	}

	return
}

// GetEKCert reads the EK certificate from NV storage.
func (tpm *TPM) GetEKCert(certIndex tpm2.TPMHandle, password string) (*x509.Certificate, error) {
	certBytes, err := tpm.ReadFromNVStorage(certIndex, password)
	if err != nil {
		return nil, fmt.Errorf("failed to read EK certificate from NV storage: %w", err)
	}
	return attestHelper.ParseEKCertificate(certBytes)
}

// MakeCredential creates credential/secret challenge tied to objectName.
func (tpm *TPM) MakeCredential(handle tpm2.TPMHandle, objectName []byte, credential []byte) (encryptedSecret, encryptedCredential []byte, err error) {
	tpmTransport := transport.FromReadWriter(tpm.rwc)
	cmd := tpm2.MakeCredential{
		Handle:     handle,
		Credential: tpm2.TPM2BDigest{Buffer: credential},
		ObjectName: tpm2.TPM2BName{Buffer: objectName},
	}
	resp, err := cmd.Execute(tpmTransport)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to execute MakeCredential command: %w", err)
	}
	return resp.Secret.Buffer, resp.CredentialBlob.Buffer, nil
}

// ActivateCredential decrypts the credential/secret challenge tied to activeHandle, then returns the decrypted credential.
func (tpm *TPM) ActivateCredential(activateHandle, keyHandle tpm2.TPMHandle, password string, encryptedSecret, encryptedCredential []byte) ([]byte, error) {
	passwordBytes := []byte(password)
	tpmTransport := transport.FromReadWriter(tpm.rwc)

	// with the legacy tpm2 API (https://fburl.com/ml5d7gju), we could have done the same
	// but without the need to get the name of the key and the activate handle, meaning
	// we could have saved 2 TPM commands.
	// T198605377 to investigate if we can do the same with the new tpm2 API
	keyName, err := getObjectName(tpm, keyHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to get object name: %w", err)
	}
	activateName, err := getObjectName(tpm, activateHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to get object name: %w", err)
	}

	cmd := tpm2.ActivateCredential{
		ActivateHandle: tpm2.NamedHandle{
			Handle: activateHandle,
			Name:   *activateName,
		},
		KeyHandle: tpm2.AuthHandle{
			Handle: keyHandle,
			Name:   *keyName,
			Auth:   tpm2.Policy(tpm2.TPMAlgSHA256, 16, ekPolicy(passwordBytes)),
		},
		CredentialBlob: tpm2.TPM2BIDObject{Buffer: encryptedCredential},
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: encryptedSecret},
	}
	resp, err := cmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("failed to execute ActivateCredentials command: %w", err)
	}
	return resp.CertInfo.Buffer, nil
}

// SolveChallenge takes an attestation server generated HMAC key wrapped with the EK and uses
// it to sign a certification for the provided activateHandle. This is used to activate an AK
// using a normal attestation that then also embeds the TPM firmware version.
func (tpm *TPM) SolveChallenge(activateHandle tpm2.NamedHandle,
	creationHash []byte, creationTicket tpm2.TPMTTKCreation,
	ekHandle tpm2.TPMHandle, password string,
	hmacPublic, hmacDuplicate, hmacInSymSeed []byte) (*tpm2.CertifyCreationResponse, error) {
	tpmTransport := transport.FromReadWriter(tpm.rwc)

	passwordBytes := []byte(password)
	ekPublicStruct, err := getObjectPublic(tpm, ekHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to get EK object public struct: %w", err)
	}

	ekName, err := tpm2.ObjectName(ekPublicStruct)
	if err != nil {
		return nil, fmt.Errorf("failed to get EK object name: %w", err)
	}

	var authSession tpm2.Session
	// Check the `UserWithAuth` attribute of the EK public key to determine if we are using the low range (L-2) vs the high range (H-3)
	// based on this we create the correct auth session.
	if ekPublicStruct.ObjectAttributes.UserWithAuth {
		authSession = tpm2.PasswordAuth(passwordBytes)
	} else {
		authSession = tpm2.Policy(tpm2.TPMAlgSHA256, 16, ekPolicy(passwordBytes))
	}

	// Import the wrapped HMAC key
	importCmd := tpm2.Import{
		ParentHandle: tpm2.AuthHandle{
			Handle: ekHandle,
			Name:   *ekName,
			Auth:   authSession,
		},
		ObjectPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](hmacPublic),
		Duplicate:    tpm2.TPM2BPrivate{Buffer: hmacDuplicate},
		InSymSeed:    tpm2.TPM2BEncryptedSecret{Buffer: hmacInSymSeed},
	}
	imported, err := importCmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("failed to import wrapped HMAC key for challenge: %w", err)
	}

	// Load the wrapped HMAC key
	loadCmd := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: ekHandle,
			Name:   *ekName,
			Auth:   authSession,
		},
		InPublic:  tpm2.BytesAs2B[tpm2.TPMTPublic](hmacPublic),
		InPrivate: imported.OutPrivate,
	}
	loaded, err := loadCmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("failed to load wrapped HMAC key for challenge: %w", err)
	}
	defer tpm.UnloadKey(loaded.ObjectHandle)

	certifyCmd := tpm2.CertifyCreation{
		SignHandle: tpm2.NamedHandle{
			Handle: loaded.ObjectHandle,
		},
		ObjectHandle: activateHandle,
		CreationHash: tpm2.TPM2BDigest{
			Buffer: creationHash,
		},
		CreationTicket: creationTicket,
	}
	certified, err := certifyCmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("failed to certify AK with wrapped HMAC key: %w", err)
	}

	return certified, nil
}

func ekPolicy(password []byte) tpm2.PolicyCallback {
	return func(tpm transport.TPM, handle tpm2.TPMISHPolicy, nonceTPM tpm2.TPM2BNonce) error {
		policyCmd := tpm2.PolicySecret{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHEndorsement,
				Auth:   tpm2.PasswordAuth(password),
			},
			PolicySession: handle,
			NonceTPM:      nonceTPM,
		}
		_, err := policyCmd.Execute(tpm)
		if err != nil {
			return fmt.Errorf("failed to execute PolicySecret command: %w", err)
		}
		return nil
	}
}

func getObjectPublic(tpm *TPM, handle tpm2.TPMHandle) (*tpm2.TPMTPublic, error) {
	tpmTransport := transport.FromReadWriter(tpm.rwc)
	resp, err := tpm2.ReadPublic{
		ObjectHandle: handle,
	}.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("failed to read public part of key: %w", err)
	}
	return resp.OutPublic.Contents()
}

func getObjectName(tpm *TPM, handle tpm2.TPMHandle) (*tpm2.TPM2BName, error) {
	publicStruct, err := getObjectPublic(tpm, handle)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public part of key: %w", err)
	}
	name, err := tpm2.ObjectName(publicStruct)
	if err != nil {
		return nil, fmt.Errorf("failed to get object name: %w", err)
	}
	return name, nil
}
