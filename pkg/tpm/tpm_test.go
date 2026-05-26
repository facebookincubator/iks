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
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
)

// TPM password we set the SWTPM hierarchies to
const tpmPassword = "TestPassword"

func startSWTPM(t *testing.T, withEK bool) string {
	tempdir := t.TempDir()
	args := []string{
		"--tpm-state",
		fmt.Sprint("dir://", tempdir),
		"--display",
		"--tpm2",
	}
	if withEK {
		args = append(args, "--createek")
	}
	setupTPMCmd := exec.Command(
		"/usr/bin/swtpm_setup", args...,
	)
	setupTPMCmd.Stdout = os.Stdout
	setupTPMCmd.Stderr = os.Stderr
	if err := setupTPMCmd.Run(); err != nil {
		t.Fatalf("failed to setup swtpm: %v", err)
	}

	sockPath := filepath.Join(tempdir, "swtpm.sock")
	ctrSockPath := filepath.Join(tempdir, "swtpm.sock.ctrl")
	swtpmCmd := exec.Command(
		"/usr/bin/swtpm",
		"socket",
		"--tpmstate",
		fmt.Sprint("dir=", tempdir),
		"--tpm2",
		"--flags",
		"startup-clear",
		"--ctrl",
		fmt.Sprintf("type=unixio,path=%s", ctrSockPath),
		"--server",
		fmt.Sprintf("type=unixio,path=%s", sockPath),
	)
	if err := swtpmCmd.Start(); err != nil {
		t.Fatalf("failed to start swtpm: %v", err)
	}
	// wait a bit for swtpm to start
	time.Sleep(1 * time.Second)
	if _, err := os.Stat(sockPath); err != nil {
		t.Fatalf("swtpm socket still doesn't exist after 1 sec: %v", err)
	}
	t.Log("swtpm started")

	t.Cleanup(func() {
		swtpmCmd.Process.Kill()
	})
	return sockPath
}

func provisionTPM(t *testing.T, tpm *TPM) {
	err := tpm.ChangeHierarchyPassword(tpm2.TPMRHOwner, "", tpmPassword)
	assert.Nil(t, err)

	err = tpm.ChangeHierarchyPassword(tpm2.TPMRHEndorsement, "", tpmPassword)
	assert.Nil(t, err)

	err = tpm.ChangeHierarchyPassword(tpm2.TPMRHLockout, "", tpmPassword)
	assert.Nil(t, err)

	err = tpm.CreateECCEK(tpmPassword)
	assert.Nil(t, err)

	err = tpm.CreateECCOwnerPK(tpmPassword)
	assert.Nil(t, err)
}

func TestTPMSealUnseal(t *testing.T) {
	// create and start a swtpm instance
	tpm, err := OpenTPM(startSWTPM(t, false))
	assert.Nil(t, err)
	defer tpm.Close()

	// provision the TPM
	provisionTPM(t, tpm)

	data := make([]byte, 128)
	_, err = rand.Read(data)
	assert.Nil(t, err)

	private, public, err := tpm.Seal(data, nil)
	assert.Nil(t, err)
	assert.NotNil(t, private)
	assert.NotNil(t, public)

	unsealed, err := tpm.Unseal(private, public, nil)
	assert.Nil(t, err)
	assert.Equal(t, data, unsealed)
}
