//go:build linux

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

	"github.com/facebookincubator/iks/pkg/blob"
	"github.com/google/go-tpm-tools/client"
	pb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm/tpmutil"
)

// OffHostWrap takes a public key of a TPM key (usually the SRK),
// and wraps data with optional PCR policy that can be later unwrapped with that TPM.
func OffHostWrap(pub crypto.PublicKey, data []byte, pcrs map[uint32][]byte) ([]byte, error) {
	importBlob, err := server.CreateImportBlob(pub, data, &pb.PCRs{
		Hash: pb.HashAlgo_SHA256,
		Pcrs: pcrs,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create import blob: %w", err)
	}

	pcrIndexes := make([]uint, 0, len(pcrs))
	for pcr := range pcrs {
		pcrIndexes = append(pcrIndexes, uint(pcr))
	}

	b := &blob.Blob{
		Btype:          blob.ImportTypeTPM,
		Private:        importBlob.Duplicate,
		Public:         importBlob.PublicArea,
		EncryptedSeeds: importBlob.EncryptedSeed,
		PCRs:           pcrIndexes,
	}

	return blob.Pack(b), nil
}

// UnwrapImportable unwraps a blob that was created with OffHostWrap.
func UnwrapImportable(tpm *TPM, duplicate, publicArea, seed []byte, pcrs []uint) ([]byte, error) {
	srk, err := client.LoadCachedKey(tpm.rwc, tpmutil.Handle(SRKECCHandle), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load SRK: %w", err)
	}

	pcrMap := make(map[uint32][]byte, len(pcrs))
	for _, pcr := range pcrs {
		pcrMap[uint32(pcr)] = nil
	}
	return srk.Import(&pb.ImportBlob{
		Duplicate:     duplicate,
		PublicArea:    publicArea,
		EncryptedSeed: seed,
		Pcrs: &pb.PCRs{
			Hash: pb.HashAlgo_SHA256,
			Pcrs: pcrMap,
		},
	})
}
