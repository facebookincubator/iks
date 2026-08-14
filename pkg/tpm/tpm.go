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
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

// NVIndexStatus represents the status of a TPM NV index.
type NVIndexStatus uint16

const (
	// NVIndexUnknown is the status used when an error occurs while checking the status of a TPM NV index.
	NVIndexUnknown NVIndexStatus = iota
	// NVIndexValid is the status used when the TPM NV index is valid, valid means existing and is already written to.
	NVIndexValid
	// NVIndexUndefined is the status used when the TPM NV index is not defined.
	NVIndexUndefined
	// NVIndexNotWritten is the status used when the TPM NV index is not written to.
	NVIndexNotWritten
)

// TPM represents a handle to a TPM2.0 device
type TPM struct {
	rwc       io.ReadWriteCloser
	srkHandle tpm2.TPMHandle
}

// ECCEKProfile describes the ECC EK selected for a TPM.
type ECCEKProfile struct {
	Curve       tpm2.TPMECCCurve
	Certificate *x509.Certificate
}

const amazonTPMVendor = "Amazon"

// authHandleInterface is just tpm2.handle. Unfortunately, tpm2 package exports a type with public fields of private types, so we have to reinvent the private types.
type authHandleInterface interface {
	HandleValue() uint32
	KnownName() *tpm2.TPM2BName
}

func authHandle(handle tpm2.TPMHandle, password string) authHandleInterface {
	if password == "" {
		return handle
	}
	return tpm2.AuthHandle{
		Handle: handle,
		Auth:   tpm2.PasswordAuth([]byte(password)),
	}
}

// ResolveECCEKProfile selects the ECC EK curve and certificate for a TPM.
// A nil certificate is valid for TPMs that do not provide an EK certificate.
func (tpm *TPM) ResolveECCEKProfile() (ECCEKProfile, error) {
	// We default to the NIST P256 key using the L-2 cert.
	// If no P256 L-2 cert, look for the P384 H-3 cert.
	for _, candidate := range [...]struct {
		index tpm2.TPMHandle
		curve tpm2.TPMECCCurve
	}{
		{EKECCCERTNVIndex, tpm2.TPMECCNistP256},
		{EKECCCERT384NVIndex, tpm2.TPMECCNistP384},
	} {
		certificate, err := tpm.GetEKCert(candidate.index, "")
		if err == nil {
			return ECCEKProfile{
				Curve:       candidate.curve,
				Certificate: certificate,
			}, nil
		}
	}

	// If neither cert is found, we check the TPM vendor.
	// If it's AWS Nitro TPM, it is P384 with no EK cert.
	curve := tpm2.TPMECCNistP256
	vendor, _, err := tpm.GetModel()
	if err != nil {
		return ECCEKProfile{}, fmt.Errorf("failed to get TPM model: %w", err)
	}

	if vendor == amazonTPMVendor {
		curve = tpm2.TPMECCNistP384
	}
	return ECCEKProfile{Curve: curve}, nil
}

func getECCEKTemplate(curve tpm2.TPMECCCurve) (tpm2.TPMTPublic, error) {
	switch curve {
	case tpm2.TPMECCNistP256:
		return tpm2.ECCEKTemplate, nil
	case tpm2.TPMECCNistP384:
		return GetECCEKP384Template(), nil
	default:
		return tpm2.TPMTPublic{}, fmt.Errorf("unsupported ECC curve: %v", curve)
	}
}

// ChangeHierarchyPassword changes the password for the provided hierarchy from
// oldPassword to newPassword.
//
// If the password is not set, oldPassword should be empty.
func (tpm *TPM) ChangeHierarchyPassword(handle tpm2.TPMHandle, oldPassword, newPassword string) error {
	tpmTransport := transport.FromReadWriter(tpm.rwc)
	cmd := tpm2.HierarchyChangeAuth{
		AuthHandle: authHandle(handle, oldPassword),
		NewAuth: tpm2.TPM2BAuth{
			Buffer: []byte(newPassword),
		},
	}
	_, err := cmd.Execute(tpmTransport)
	return err
}

// CreateECCEK defines an ECC based Endorsement Key using the provided
// endorsement hierarchy password. The key is stored into the EKRSAHandle
// persistent handle, which is treated as a generic EK handle.
func (tpm *TPM) CreateECCEK(password string) error {
	passwordBytes := []byte(password)
	tpmTransport := transport.FromReadWriter(tpm.rwc)

	profile, err := tpm.ResolveECCEKProfile()
	if err != nil {
		return err
	}
	ekTemplate, err := getECCEKTemplate(profile.Curve)
	if err != nil {
		return err
	}

	cmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth(passwordBytes),
		},
		InPublic: tpm2.New2B(ekTemplate),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: passwordBytes,
				},
			},
		},
	}
	resp, err := cmd.Execute(tpmTransport)
	if err != nil {
		return fmt.Errorf("failed to create primary: %w", err)
	}

	flushCmd := tpm2.FlushContext{
		FlushHandle: resp.ObjectHandle,
	}
	defer func() {
		_, _ = flushCmd.Execute(tpmTransport)
	}()

	evictCmd := tpm2.EvictControl{
		Auth: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(passwordBytes),
		},
		ObjectHandle: tpm2.NamedHandle{
			Handle: resp.ObjectHandle,
			Name:   resp.Name,
		},
		PersistentHandle: EKRSAHandle,
	}
	_, err = evictCmd.Execute(tpmTransport)
	if err != nil {
		return fmt.Errorf("failed to evict control: %w", err)
	}

	return nil
}

// CreateRSAEK defines an RSA based Endorsement Key using the provided
// endorsement hierarchy password. The key is stored into the EKRSAHandle
// persistent handle.
func (tpm *TPM) CreateRSAEK(password string) error {
	passwordBytes := []byte(password)
	tpmTransport := transport.FromReadWriter(tpm.rwc)
	cmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth(passwordBytes),
		},
		InPublic: tpm2.New2B(tpm2.RSAEKTemplate),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: passwordBytes,
				},
			},
		},
	}
	resp, err := cmd.Execute(tpmTransport)
	if err != nil {
		return fmt.Errorf("failed to create primary: %w", err)
	}

	flushCmd := tpm2.FlushContext{
		FlushHandle: resp.ObjectHandle,
	}
	defer func() {
		_, _ = flushCmd.Execute(tpmTransport)
	}()

	evictCmd := tpm2.EvictControl{
		Auth: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(passwordBytes),
		},
		ObjectHandle: tpm2.NamedHandle{
			Handle: resp.ObjectHandle,
			Name:   resp.Name,
		},
		PersistentHandle: EKRSAHandle,
	}
	_, err = evictCmd.Execute(tpmTransport)
	if err != nil {
		return fmt.Errorf("failed to evict control: %w", err)
	}

	return nil
}

// LoadECCEK creates and loads the ECC based Endorsement Key using the provided
// endorsement hierarchy password. The loaded handle is then returned.
func (tpm *TPM) LoadECCEK(password string, alg tpm2.TPMECCCurve) (tpm2.TPMHandle, error) {
	ekTemplate, err := getECCEKTemplate(alg)
	if err != nil {
		return 0, err
	}

	passwordBytes := []byte(password)
	tpmTransport := transport.FromReadWriter(tpm.rwc)
	cmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth(passwordBytes),
		},
		InPublic: tpm2.New2B(ekTemplate),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: passwordBytes,
				},
			},
		},
	}
	resp, err := cmd.Execute(tpmTransport)
	if err != nil {
		return 0, fmt.Errorf("failed to create primary: %w", err)
	}

	return resp.ObjectHandle, nil
}

// CreateECCOwnerPK defines a NIST P256 based Owner Primary Key using the
// provided owner hierarchy password. The key is stored into the SRKECCHandle
// persistent handle.
func (tpm *TPM) CreateECCOwnerPK(password string) error {
	passwordBytes := []byte(password)
	tpmTransport := transport.FromReadWriter(tpm.rwc)
	cmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(passwordBytes),
		},
		InPublic: tpm2.New2B(tpm2.ECCSRKTemplate),
	}
	resp, err := cmd.Execute(tpmTransport)
	if err != nil {
		return fmt.Errorf("failed to create primary: %w", err)
	}

	flushCmd := tpm2.FlushContext{
		FlushHandle: resp.ObjectHandle,
	}
	defer func() {
		_, _ = flushCmd.Execute(tpmTransport)
	}()

	evictCmd := tpm2.EvictControl{
		Auth: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(passwordBytes),
		},
		ObjectHandle: tpm2.NamedHandle{
			Handle: resp.ObjectHandle,
			Name:   resp.Name,
		},
		PersistentHandle: SRKECCHandle,
	}
	_, err = evictCmd.Execute(tpmTransport)
	if err != nil {
		return fmt.Errorf("failed to evict control: %w", err)
	}

	return nil
}

// DoSelfTest asks the TPM to do a full self test
func (tpm *TPM) DoSelfTest() error {
	var CmdSelfTest tpmutil.Command = 0x00000143

	_, code, err := tpmutil.RunCommand(tpm.rwc, tpmutil.Tag(tpm2.TPMSTNoSessions), CmdSelfTest, true)
	if err != nil {
		return err
	}

	// Ideally we want a full decode of this, but decodeResponse is not exported from the tpm2
	// package. Do this for now while we look at updating to a more recent upstream tpm2.
	if code != tpmutil.RCSuccess {
		return fmt.Errorf("self test failure: %04X", code)
	}

	return nil
}

func getProperty(tpm io.ReadWriteCloser, prop tpm2.TPMPT) ([]byte, error) {
	tpmTransport := transport.FromReadWriter(tpm)
	cmd := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(prop),
		PropertyCount: 1,
	}
	resp, err := cmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("could not get property %v: %w", prop, err)
	}

	props, err := resp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return nil, fmt.Errorf("could not read property from capability response data %v: %w", prop, err)
	}
	if len(props.TPMProperty) != 1 {
		return nil, fmt.Errorf("expected 1 property, got %d", len(props.TPMProperty))
	}
	val := props.TPMProperty[0].Value
	b, err := tpmutil.Pack(val)
	if err != nil {
		return nil, fmt.Errorf("failed to pack prop value: %w", err)
	}
	return b, nil
}

// GetPropertyString returns the given TPM prop as a string. Trailing NULs will be removed.
func (tpm *TPM) GetPropertyString(prop tpm2.TPMPT) (string, error) {
	b, err := getProperty(tpm.rwc, prop)
	if err != nil {
		return "", err
	}

	// Trim tailing NULs
	for last := len(b); last > 0 && b[last-1] == 0; last-- {
		b = b[:last-1]
	}

	return string(b), nil
}

// GetPropertyUInt32 returns the given TPM2 prop as a uint32.
func (tpm *TPM) GetPropertyUInt32(prop tpm2.TPMPT) (uint32, error) {
	b, err := getProperty(tpm.rwc, prop)
	if err != nil {
		return 0, err
	}

	return binary.BigEndian.Uint32(b), nil
}

// GetModel returns the TPM vendor + model
// It handles differences in the ways different vendors encode this information.
func (tpm *TPM) GetModel() (string, string, error) {
	var (
		model   string
		vendor  string
		errMsgs []string
	)

	vendor, err := tpm.GetPropertyString(tpm2.TPMPTManufacturer)
	if err != nil {
		return "", "", fmt.Errorf("could not get vendor: %w", err)
	}
	vendor = strings.TrimSpace(vendor)

	// By default return all of the Vendor string properties
	properties := []tpm2.TPMPT{
		tpm2.TPMPTVendorString1,
		tpm2.TPMPTVendorString2,
		tpm2.TPMPTVendorString3,
		tpm2.TPMPTVendorString4,
	}

	if vendor == "NTC" {
		// Nuvoton use STRING_1 + STRING_2 for the model details
		// STRING_3 is for internal use, and non-ASCII
		// STRING_4 is "rls" for production TPMs
		properties = []tpm2.TPMPT{
			tpm2.TPMPTVendorString1,
			tpm2.TPMPTVendorString2,
		}
	}

	for _, property := range properties {
		val, err := tpm.GetPropertyString(property)
		if err == nil {
			model += val
		} else {
			errMsgs = append(errMsgs, fmt.Sprintf("failed to get property %v: %v", property, err))
		}
	}

	if len(errMsgs) != 0 {
		return "", "", fmt.Errorf("could not get model: %s", strings.Join(errMsgs, ", "))
	}

	// Older Nuvoton TPMs don't have a valid model name in VendorString.
	// We see these in older Dell machines, and have confirmed with Nuvoton
	// this is the correct mapping.
	if vendor == "NTC" && model == "rlsNPCT" {
		model = "NPCT65x"
	}

	// Older STM TPMs have non-ASCII vendor strings, so we need to look at
	// the major firmware version. Breakdown provided via conversation with
	// STM FAE.
	if vendor == "STM" && !strings.HasPrefix(model, "ST") {
		fwVer, err := tpm.GetPropertyUInt32(tpm2.TPMPTFirmwareVersion1)
		if err != nil {
			return "", "", fmt.Errorf("could not get STM firmware version: %w", err)
		}
		switch fwVer >> 16 {
		case 0x01:
			model = "ST33TPHF2XSPI"
		case 0x02:
			model = "ST33TPHF2XI2C"
		case 0x09:
			// For completeness. We shouldn't see this, it should
			// have an ASCII vendor string.
			model = "ST33KTPM2X"
		case 0x49:
			model = "ST33TPHF2E"
		case 0x4A:
			model = "ST33TPHF20"
		default:
			model = "ST33??????"
		}
	}

	switch vendor {
	case "AMZN":
		vendor = "Amazon"
	case "GOOG":
		vendor = "Google"
	case "IFX":
		vendor = "Infineon"
	case "NTC":
		vendor = "Nuvoton"
	case "STM":
		vendor = "STMicroelectronics"
	}

	return vendor, model, nil
}

// TPMPermanentInfo represents the TPM attributes from TPMA_PERMANENT, which are not
// changed as a result of TPM_Init() or TPM2_Startup()
// TCG TPM Rev 2.0 Part 2 Structures rev 01.38 8.6 Table 34
type TPMPermanentInfo struct {
	OwnerAuthSet       bool
	EndorsementAuthSet bool
	LockoutAuthSet     bool
	DisableClear       bool
	InLockout          bool
	TpmGeneratedEPS    bool
}

// GetTPMPermanentInfo retrieves the TPMA_PERMANENT information from the TPM and
// parses it into a TPMPermanentInfo structure.
func (tpm *TPM) GetTPMPermanentInfo() (*TPMPermanentInfo, error) {
	permProps, err := tpm.GetPropertyUInt32(tpm2.TPMPTPermanent)
	if err != nil {
		return nil, err
	}

	return &TPMPermanentInfo{
		OwnerAuthSet:       (permProps & (1 << 0)) != 0,
		EndorsementAuthSet: (permProps & (1 << 1)) != 0,
		LockoutAuthSet:     (permProps & (1 << 2)) != 0,
		DisableClear:       (permProps & (1 << 8)) != 0,
		InLockout:          (permProps & (1 << 9)) != 0,
		TpmGeneratedEPS:    (permProps & (1 << 10)) != 0,
	}, nil
}

// TPMClockInfo represents the TPM attributes from TPMS_TIME_INFO struct.
type TPMClockInfo struct {
	Time         uint64
	Clock        uint64
	ResetCount   uint32
	RestartCount uint32
}

// GetTPMClockInfo retrieves the TPM clock information from the TPM and parses it into a TPMClockInfo structure
func (tpm *TPM) GetTPMClockInfo() (*TPMClockInfo, error) {
	respBytes, code, err := tpmutil.RunCommand(tpm.rwc, tpmutil.Tag(tpm2.TPMSTNoSessions), tpmutil.Command(tpm2.TPMCCReadClock))
	if err != nil {
		return nil, err
	}
	if code != tpmutil.RCSuccess {
		return nil, fmt.Errorf("readClock Command failed: %04X", code)
	}
	var clockInfo TPMClockInfo
	_, err = tpmutil.Unpack(
		respBytes,
		&clockInfo.Time,
		&clockInfo.Clock,
		&clockInfo.ResetCount,
		&clockInfo.RestartCount,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack readClock Command response: %w", err)
	}

	return &clockInfo, nil
}

// NewSession creates a new Policy Session and returns it, along with a function to close the session.
func (tpm *TPM) NewSession() (tpm2.Session, func() error, error) {
	tpmTransport := transport.FromReadWriter(tpm.rwc)
	session, sessionCloser, err := tpm2.PolicySession(tpmTransport, tpm2.TPMAlgSHA256, crypto.SHA256.Size())
	if err != nil {
		return nil, nil, err
	}
	return session, sessionCloser, nil
}

// PCRPolicy creates a new PCR-based policy and attaches it to the provided session.
func (tpm *TPM) PCRPolicy(sessionHandle tpm2.TPMHandle, pcrSelection tpm2.TPMLPCRSelection) (tpm2.TPM2BDigest, error) {
	tpmTransport := transport.FromReadWriter(tpm.rwc)

	// Setting expectedDigest to empty will create the policy based on current PCR values
	expectedDigest := tpm2.TPM2BDigest{}

	// Execute PolicyPCR
	_, err := tpm2.PolicyPCR{PolicySession: sessionHandle, PcrDigest: expectedDigest, Pcrs: pcrSelection}.Execute(tpmTransport)
	if err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("Error Executing PolicyPCR: %w", err)
	}

	// Execute PolicyGetDigest
	resp, err := tpm2.PolicyGetDigest{PolicySession: sessionHandle}.Execute(tpmTransport)
	if err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("Error Executing PolicyGetDigest: %w", err)
	}

	return resp.PolicyDigest, nil
}

// SelectPCRs reads the provided PCRs indexes and returns the selection as a TPML_PCR_SELECTION
func (tpm *TPM) SelectPCRs(pcrs ...uint) tpm2.TPMLPCRSelection {
	// Select PCRs
	pcrSelection := tpm2.TPMSPCRSelection{
		Hash:      tpm2.TPMAlgSHA256,
		PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs...),
	}
	// Create List from Selection
	pcrSelectionList := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{pcrSelection},
	}

	return pcrSelectionList
}

// PCR represents a TPM Platform Register.
type PCR struct {
	Digest []byte
	Index  uint
}

// PolicyPCRs represents a list of PCR index that are used to match a policy.
type PolicyPCRs struct {
	PCRs []uint
}

// getPCRHashAlg returns our preferred available PCR hash algorithm.
// We pefer SHA2-256, but can cope with SHA2-384 or SHA2-512 if that's all
// that's on offer.
func (tpm *TPM) getPCRHashAlg() (tpm2.TPMAlgID, error) {
	tpmTransport := transport.FromReadWriter(tpm.rwc)
	alg := tpm2.TPMAlgID(0)
	getCapCmd := tpm2.GetCapability{
		Capability:    tpm2.TPMCapPCRs,
		PropertyCount: 1,
	}
	getCapResp, err := getCapCmd.Execute(tpmTransport)
	if err != nil {
		return 0, fmt.Errorf("could not execute GetCapabilty(TPMCapPCRs) command, property: %w", err)
	}
	algs, err := getCapResp.CapabilityData.Data.AssignedPCR()
	if err != nil {
		return 0, fmt.Errorf("could not read TPM PCR algorithms: %w", err)
	}
	for _, a := range algs.PCRSelections {
		// Make sure we actually have PCR measurements using this hash.
		// PCRSelect is an array of 8-bit values, each representing 8
		// PCRs. If a bit is set, this means that TPM has that PCR in
		// this bank. We want a bank with all 24 standard PCRs.
		if len(a.PCRSelect) != 3 || a.PCRSelect[0] != 255 ||
			a.PCRSelect[1] != 255 || a.PCRSelect[2] != 255 {
			continue
		}

		if a.Hash == tpm2.TPMAlgSHA256 {
			alg = tpm2.TPMAlgSHA256
			break
		} else if a.Hash == tpm2.TPMAlgSHA384 {
			alg = tpm2.TPMAlgSHA384
		} else if a.Hash == tpm2.TPMAlgSHA512 && alg != tpm2.TPMAlgSHA384 {
			alg = tpm2.TPMAlgSHA512
		}
	}
	if alg == 0 {
		return 0, fmt.Errorf("could not find suitable TPM PCR algorithm")
	}

	return alg, nil
}

// ReadPCRs reads the provided PCR indexes and returns a slice of PCRs (i.e. Index, Digest pairs).
func (tpm *TPM) ReadPCRs(pcrs ...uint) ([]PCR, error) {
	values := make([]PCR, 0, len(pcrs))
	tpmTransport := transport.FromReadWriter(tpm.rwc)
	var pcrMask uint32
	for _, pcr := range pcrs {
		pcrMask |= 1 << pcr
	}

	alg, err := tpm.getPCRHashAlg()
	if err != nil {
		return nil, err
	}

	// TPM might not read all the requested PCRs because the output buffer is limited
	// That's why we might need to call the command multiple times.
	// See TPM2 Specs Part 2, section 22.4.1
	for {
		cmd := tpm2.PCRRead{
			PCRSelectionIn: tpm2.TPMLPCRSelection{
				PCRSelections: []tpm2.TPMSPCRSelection{
					{
						Hash:      alg,
						PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs...),
					},
				},
			},
		}
		resp, err := cmd.Execute(tpmTransport)
		if err != nil {
			return nil, fmt.Errorf("failed to execute PCRRead command: %w", err)
		}
		if len(resp.PCRSelectionOut.PCRSelections) == 0 ||
			len(resp.PCRSelectionOut.PCRSelections[0].PCRSelect) == 0 {
			// This might happen if we ask for a PCR that is not present in the TPM
			break
		}
		var digestIndex int
		// PCRSelect is an array of 8-bit values, each representing 8 PCRs
		// if a bit is set, this means that TPM has read the value of such PCR and
		// returned it in the Digests array.
		// See TPM2 Specs Part 2, section 22.4.1
		for j, bits := range resp.PCRSelectionOut.PCRSelections[0].PCRSelect {
			// masking out the bits for the PCRs that we read
			pcrMask &= ^(uint32(bits) << (j * 8))
			// calculating pcrIndexes for the returned PCR Values
			for i := range 8 {
				if bits&(1<<i) == 0 {
					continue
				}
				pcrIndex := j*8 + i
				values = append(values, PCR{
					Index:  uint(pcrIndex),
					Digest: resp.PCRValues.Digests[digestIndex].Buffer,
				})
				digestIndex++
			}
		}
		// break after reading all the PCRs
		if pcrMask == 0 {
			break
		}
		// otherwise, we need to read the remaining PCRs
		var remPCRs []uint
		for _, pcr := range pcrs {
			if pcrMask&(1<<pcr) != 0 {
				remPCRs = append(remPCRs, pcr)
			}
		}
		pcrs = remPCRs
	}
	if pcrMask != 0 {
		return values, fmt.Errorf("some PCRs are not present: %v", pcrs)
	}
	return values, nil
}

// ExtendPCR extends the provided PCR index with the provided hash.
// The hash is expected to be of the same size as the hashing algorithm used (SHA256).
func (tpm *TPM) ExtendPCR(pcr uint, hash []byte) error {
	tpmTransport := transport.FromReadWriter(tpm.rwc)
	cmd := tpm2.PCRExtend{
		PCRHandle: tpm2.TPMHandle(pcr),
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{
				{
					HashAlg: tpm2.TPMAlgSHA256,
					Digest:  hash,
				},
			},
		},
	}
	_, err := cmd.Execute(tpmTransport)
	if err != nil {
		return fmt.Errorf("failed to execute PCRExtend command: %w", err)
	}
	return nil
}

// ResetPCR resets the provided PCR index.
func (tpm *TPM) ResetPCR(pcr uint) error {
	tpmTransport := transport.FromReadWriter(tpm.rwc)
	cmd := tpm2.PCRReset{
		PCRHandle: tpm2.TPMHandle(pcr),
	}
	if _, err := cmd.Execute(tpmTransport); err != nil {
		return fmt.Errorf("failed to execute PCRReset for PCR %v command: %w", pcr, err)
	}
	return nil
}

// ReadHandle reads the provided TPM key handle and returns the public key data
// as a byte slice in DER format.
func (tpm *TPM) ReadHandle(handle tpm2.TPMHandle) ([]byte, error) {
	key, err := tpm.ReadPublicKey(handle)
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKIXPublicKey(key)
}

// Seal seals the sensitiveData using the TPM SRK. It returns the private and public parts of the
// sealed data (but the private data is sealed and can only be decrypted by the TPM that created
// it). A pointer to a policy digest can be provided to restrict the unsealing of the data.
// If no policy is needed the function expects nil
func (tpm *TPM) Seal(sensitiveData []byte, policy *tpm2.TPM2BDigest) ([]byte, []byte, error) {
	tpmTransport := transport.FromReadWriter(tpm.rwc)
	inPublic := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:     true,
			FixedParent:  true,
			UserWithAuth: true,
		},
	}
	if policy != nil {
		inPublic.AuthPolicy = *policy
		inPublic.ObjectAttributes.UserWithAuth = false
	}
	cmd := tpm2.Create{
		ParentHandle: tpm2.NamedHandle{
			Handle: tpm.srkHandle,
		},
		InPublic: tpm2.New2B(inPublic),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
					Buffer: sensitiveData,
				}),
			},
		},
	}
	resp, err := cmd.Execute(tpmTransport)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create key: %w", err)
	}
	outPublic, outPrivate := resp.OutPublic.Bytes(), resp.OutPrivate.Buffer
	return outPrivate, outPublic, nil
}

// Unseal takes the private and public data, passes them to the TPM to decrypt, and returns the
// sensitive data. Optionally, an auth session can be provided to prove fulfilment of any sealing policy.
// If `nil` session is provided, the function will attempt to unseal without a session.
func (tpm *TPM) Unseal(private []byte, public []byte, sess tpm2.Session) ([]byte, error) {
	inPublic, err := ToPublic(public)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}
	inPrivate := ToPrivate(private)

	tpmTransport := transport.FromReadWriter(tpm.rwc)
	cmd := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: tpm.srkHandle,
		},
		InPublic:  *inPublic,
		InPrivate: *inPrivate,
	}
	resp, err := cmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("failed to load TPM object: %w", err)
	}
	flushCmd := tpm2.FlushContext{
		FlushHandle: resp.ObjectHandle,
	}
	defer func() {
		for range 3 {
			if _, err := flushCmd.Execute(tpmTransport); err == nil {
				break
			}
			time.Sleep(1 * time.Second)
		}
	}()
	unSealCmd := tpm2.Unseal{
		ItemHandle: tpm2.NamedHandle{
			Handle: resp.ObjectHandle,
			Name:   resp.Name,
		},
	}
	if sess != nil {
		// If a session is provided, use it to unseal the object
		unSealCmd = tpm2.Unseal{
			ItemHandle: tpm2.AuthHandle{
				Handle: resp.ObjectHandle,
				Name:   resp.Name,
				Auth:   sess,
			},
		}
	}
	unSealResp, err := unSealCmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("failed to unseal: %w", err)
	}
	return unSealResp.OutData.Buffer, nil
}

// CreateKey creates a new key in the TPM using the provided owner handle and password. It returns the wrapped public and private key data and object creation data.
func (tpm *TPM) CreateKey(owner tpm2.TPMHandle, password string, keyTemplate tpm2.TPMTPublic) (public, private, creationData, creationHash []byte, creationTicket *tpm2.TPMTTKCreation, err error) {
	passwordBytes := []byte(password)
	tpmTransport := transport.FromReadWriter(tpm.rwc)
	cmd := tpm2.Create{
		ParentHandle: tpm2.NamedHandle{
			Handle: owner,
		},
		InPublic: tpm2.New2B(keyTemplate),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: passwordBytes,
				},
			},
		},
	}
	resp, err := cmd.Execute(tpmTransport)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to create key: %w", err)
	}
	public, private = resp.OutPublic.Bytes(), resp.OutPrivate.Buffer
	creationData, creationHash = resp.CreationData.Bytes(), resp.CreationHash.Buffer
	creationTicket = &resp.CreationTicket
	return public, private, creationData, creationHash, creationTicket, nil
}

// LoadKey loads the provided public and private key data into the TPM and returns the handle.
func (tpm *TPM) LoadKey(owner tpm2.TPMHandle, public, private []byte) (tpm2.TPMHandle, error) {
	inPublic, err := ToPublic(public)
	if err != nil {
		return 0, fmt.Errorf("failed to read public key: %w", err)
	}
	inPrivate := ToPrivate(private)

	tpmTransport := transport.FromReadWriter(tpm.rwc)
	cmd := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: owner,
		},
		InPublic:  *inPublic,
		InPrivate: *inPrivate,
	}
	resp, err := cmd.Execute(tpmTransport)
	if err != nil {
		return 0, fmt.Errorf("failed to load key: %w", err)
	}
	return resp.ObjectHandle, nil
}

// UnloadKey unloads the provided key handle from the TPM.
func (tpm *TPM) UnloadKey(handle tpm2.TPMHandle) error {
	tpmTransport := transport.FromReadWriter(tpm.rwc)
	cmd := tpm2.FlushContext{
		FlushHandle: handle,
	}
	_, err := cmd.Execute(tpmTransport)
	return err
}

// Sign signs the digest with the provided key handle and returns the signature.
func (tpm *TPM) Sign(handle tpm2.TPMHandle, alg tpm2.TPMAlgID, digest []byte) ([]byte, error) {
	tpmTransport := transport.FromReadWriter(tpm.rwc)
	cmd := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{
			Handle: handle,
		},
		Digest: tpm2.TPM2BDigest{
			Buffer: digest,
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
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}
	resp, err := cmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	signature, err := GetSignature(resp.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to get signature: %w", err)
	}
	return signature, nil
}

// SignWithPolicy signs the digest using a key that requires PCR policy authorization.
// It creates a policy session, satisfies the PCR policy, and then signs the digest.
func (tpm *TPM) SignWithPolicy(handle tpm2.TPMHandle, alg tpm2.TPMAlgID, digest []byte, pcrs []uint) ([]byte, error) {
	tpmTransport := transport.FromReadWriter(tpm.rwc)

	// Get the object name for the key handle
	keyName, err := getObjectName(tpm, handle)
	if err != nil {
		return nil, fmt.Errorf("failed to get key object name: %w", err)
	}

	cmd := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: handle,
			Name:   *keyName,
			Auth:   tpm2.Policy(tpm2.TPMAlgSHA256, 16, pcrPolicyCallback(tpm, pcrs)),
		},
		Digest: tpm2.TPM2BDigest{
			Buffer: digest,
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
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}
	resp, err := cmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with policy: %w", err)
	}

	signature, err := GetSignature(resp.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to get signature: %w", err)
	}
	return signature, nil
}

// ReadPublic reads the public area of the provided TPM handle and returns it as a byte slice.
func (tpm *TPM) ReadPublic(handle tpm2.TPMHandle) ([]byte, error) {
	tpmTransport := transport.FromReadWriter(tpm.rwc)
	cmd := tpm2.ReadPublic{
		ObjectHandle: handle,
	}
	resp, err := cmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("failed to read public area of handle %v: %w", handle, err)
	}
	return resp.OutPublic.Bytes(), nil
}

// ReadPublicKey reads the public key from the provided TPM handle and returns it as a crypto.PublicKey.
func (tpm *TPM) ReadPublicKey(handle tpm2.TPMHandle) (crypto.PublicKey, error) {
	tpmTransport := transport.FromReadWriter(tpm.rwc)
	cmd := tpm2.ReadPublic{
		ObjectHandle: handle,
	}
	resp, err := cmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("failed to read public part of handle %v: %w", handle, err)
	}

	pc, err := resp.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed to read public content: %w", err)
	}

	return ParsePublicKey(pc)
}

// Startup attempts to start up the TPM
func (tpm *TPM) Startup(startupType tpm2.TPMSU) error {
	tpmTransport := transport.FromReadWriter(tpm.rwc)
	cmd := tpm2.Startup{StartupType: startupType}
	_, err := cmd.Execute(tpmTransport)

	return err
}

// Shutdown attempts to shut down the TPM
func (tpm *TPM) Shutdown(shutdownType tpm2.TPMSU) error {
	tpmTransport := transport.FromReadWriter(tpm.rwc)
	cmd := tpm2.Shutdown{ShutdownType: shutdownType}
	_, err := cmd.Execute(tpmTransport)

	return err
}

// Clear removes all TPM context associated with the owner, removing resident objects, generating
// a new storage seed, and clearing the owner/endorsement/lockout passwords.
func (tpm *TPM) Clear(password string) error {
	tpmTransport := transport.FromReadWriter(tpm.rwc)
	cmd := tpm2.Clear{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHLockout,
			Auth:   tpm2.PasswordAuth([]byte(password)),
		},
	}
	_, err := cmd.Execute(tpmTransport)
	if err != nil {
		return fmt.Errorf("failed to execute Clear command: %w", err)
	}
	return nil
}

// GetRandomBytes returns random bytes from the TPM.
func (tpm *TPM) GetRandomBytes(size uint16) ([]byte, error) {
	tpmTransport := transport.FromReadWriter(tpm.rwc)
	cmd := tpm2.GetRandom{
		BytesRequested: size,
	}
	resp, err := cmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("failed to execute GetRandom command: %w", err)
	}
	return resp.RandomBytes.Buffer, nil
}

// InitNVStorage initializes the provided TPM NVRAM index if it doesn't exist.
func (tpm *TPM) InitNVStorage(handle tpm2.TPMHandle, password string, size uint16) error {
	exists, err := tpm.NVHandleExists(handle)
	if err != nil {
		return err
	}

	if !exists {
		return tpm.DefineNVStorage(handle, password, size)
	}

	return nil
}

// ReadFromNVStorage reads the provided TPM NVRAM index and returns the raw data.
func (tpm *TPM) ReadFromNVStorage(handle tpm2.TPMHandle, password string) ([]byte, error) {
	tpmTransport := transport.FromReadWriter(tpm.rwc)
	// get max possible data size in one NV read.
	getCapCmd := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTNVBufferMax),
		PropertyCount: 1,
	}
	getCapResp, err := getCapCmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("could not execute GetCapabilty(TPMCapTPMProperties) command, property %v: %w", tpm2.TPMPTNVBufferMax, err)
	}
	props, err := getCapResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return nil, fmt.Errorf("could not read TPM properties: %w", err)
	}
	maxBlockSize := props.TPMProperty[0].Value
	// get data size from NV index public area.
	readPublicCmd := tpm2.NVReadPublic{
		NVIndex: handle,
	}
	pub, err := readPublicCmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("failed to execute NVPublicRead command: %w", err)
	}
	public, err := pub.NVPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed to read NV public area: %w", err)
	}
	dataSize := public.DataSize

	buffer := make([]byte, 0, dataSize)
	readFunc := func(handle tpm2.TPMHandle, size, offset uint16) ([]byte, error) {
		// use handle as authHandle to use the password as authValue, see TPM2 TCG Part2 9.22.
		cmd := tpm2.NVRead{
			AuthHandle: tpm2.AuthHandle{
				Handle: handle,
				Auth:   tpm2.PasswordAuth([]byte(password)),
				Name: tpm2.TPM2BName{
					// name is not used in password sessions, but API requires non empty value.
					Buffer: []byte{0x00},
				},
			},
			NVIndex: tpm2.NamedHandle{
				Handle: handle,
			},
			Size:   size,
			Offset: offset,
		}
		resp, err := cmd.Execute(tpmTransport)
		if err != nil {
			return nil, fmt.Errorf("failed to execute NVRead command: %w", err)
		}
		return resp.Data.Buffer, nil
	}
	for len(buffer) < int(dataSize) {
		readSize := min(uint16(maxBlockSize), dataSize-uint16(len(buffer)))
		data, err := readFunc(handle, readSize, uint16(len(buffer)))
		if err != nil {
			return nil, fmt.Errorf("failed to read data from NV index %v, offset %v: %w", handle, len(buffer), err)
		}
		buffer = append(buffer, data...)
	}

	return buffer, nil
}

// WriteToNVStorage writes the provided data to the provided TPM NVRAM index.
func (tpm *TPM) WriteToNVStorage(handle tpm2.TPMHandle, data []byte, password string) error {
	tpmTransport := transport.FromReadWriter(tpm.rwc)
	cmd := tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{
			Handle: handle,
			Auth:   tpm2.PasswordAuth([]byte(password)),
			Name: tpm2.TPM2BName{
				// name is not used in password sessions, but API requires non empty value.
				Buffer: []byte{0x00},
			},
		},
		NVIndex: tpm2.NamedHandle{
			Handle: handle,
		},
		Data: tpm2.TPM2BMaxNVBuffer{
			Buffer: data,
		},
		Offset: 0,
	}
	_, err := cmd.Execute(tpmTransport)
	return err
}

// GetHandles returns all the handles of the given type present in the TPM
func (tpm *TPM) GetHandles(handleType tpm2.TPMHT) ([]tpm2.TPMHandle, error) {
	// NV handles range from 0x01000000 to 0x01FFFFFF which makes a total of 0x01000000 possible indexes,
	// see TCG "Registry of Reserved TPM 2.0 Handles and Localities" Section 2.2 Table 2, so let's use that
	// as the max handle count we might want.
	var (
		MaxHandleCount uint32 = 0x01000000
	)

	tpmTransport := transport.FromReadWriter(tpm.rwc)
	cmd := tpm2.GetCapability{
		Capability: tpm2.TPMCapHandles,
		// type of handles to return depends on the Most Significant Octat (MSO), see TPM2 TCG Part3 30.2.1.
		Property:      uint32(handleType) << 24,
		PropertyCount: MaxHandleCount,
	}
	resp, err := cmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("failed to execute GetCapabilities command reading NV handles: %w", err)
	}
	handles, err := resp.CapabilityData.Data.Handles()
	if err != nil {
		return nil, fmt.Errorf("failed to read Handles from command response: %w", err)
	}

	return handles.Handle, err
}

// NVHandleExists returns true if the provided handle is an existing TPM handle.
func (tpm *TPM) NVHandleExists(handle tpm2.TPMHandle) (bool, error) {
	handles, err := tpm.GetHandles(tpm2.TPMHTNVIndex)
	if err != nil {
		return false, err
	}

	return slices.Contains(handles, handle), nil
}

// CheckNVHandle checks the status and size of an existing TPM NV index, if the dataSize is < 0 it will be ignored.
func (tpm *TPM) CheckNVHandle(handle tpm2.TPMHandle, dataSize int) (NVIndexStatus, error) {
	tpmTransport := transport.FromReadWriter(tpm.rwc)
	cmd := tpm2.NVReadPublic{
		NVIndex: handle,
	}
	resp, err := cmd.Execute(tpmTransport)
	if err != nil {
		return NVIndexUnknown, fmt.Errorf("failed to execute NVPublicRead command: %w", err)
	}
	nvPublic, err := resp.NVPublic.Contents()
	if err != nil {
		return NVIndexUnknown, fmt.Errorf("failed to read NV public area: %w", err)
	}
	if dataSize >= 0 && nvPublic.DataSize != uint16(dataSize) {
		return NVIndexUnknown, fmt.Errorf("invalid NV index size. Expected %v found %v", dataSize, nvPublic.DataSize)
	}
	if !nvPublic.Attributes.Written {
		return NVIndexNotWritten, nil
	}

	return NVIndexValid, nil
}

// NVStorageStatus returns the status and size of the provided TPM NV index, if the dataSize is < 0 it will be ignored.
func (tpm *TPM) NVStorageStatus(handle tpm2.TPMHandle, dataSize int) (NVIndexStatus, error) {
	exists, err := tpm.NVHandleExists(handle)
	if err != nil {
		return NVIndexUnknown, err
	}
	if !exists {
		return NVIndexUndefined, nil
	}

	return tpm.CheckNVHandle(handle, dataSize)
}

// DefineNVStorage defines a new TPM NVRAM index with the provided handle and size.
func (tpm *TPM) DefineNVStorage(handle tpm2.TPMHandle, password string, size uint16) error {
	tpmTransport := transport.FromReadWriter(tpm.rwc)
	cmd := tpm2.NVDefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
			NVIndex: handle,
			NameAlg: tpm2.TPMAlgSHA256,
			Attributes: tpm2.TPMANV{
				AuthWrite: true,
				AuthRead:  true,
			},
			DataSize: size,
		}),
		Auth: tpm2.TPM2BAuth{
			Buffer: []byte(password),
		},
	}
	_, err := cmd.Execute(tpmTransport)
	return err
}

// Close closes the provided TPM handle. It should not be used afterwards.
func (tpm *TPM) Close() {
	tpm.rwc.Close()
}

// ToPublic converts a serialized TPM Object's public area (the result of legacy tpm2),
// to a TPM2BPublic structure (the one used by the new tpm2 API).
func ToPublic(public []byte) (*tpm2.TPM2BPublic, error) {
	// construct a serialized TPM2B struct.
	var marshaledPublic bytes.Buffer
	err := binary.Write(&marshaledPublic, binary.BigEndian, uint16(len(public)))
	if err != nil {
		return nil, fmt.Errorf("failed to serialize public length to binary: %w", err)
	}
	_, err = marshaledPublic.Write(public)
	if err != nil {
		return nil, fmt.Errorf("failed to create marshaled TPM2B struct: %w", err)
	}

	return tpm2.Unmarshal[tpm2.TPM2BPublic](marshaledPublic.Bytes())
}

// ToPrivate converts a serialized TPM Object's private area (the result of legacy tpm2),
// to a TPM2BPrivate structure (the one used by the new tpm2 API).
func ToPrivate(private []byte) *tpm2.TPM2BPrivate {
	inPrivate := tpm2.TPM2BPrivate{
		Buffer: private,
	}
	return &inPrivate
}

// ParsePublicKey parses the provided TPM public key from TPM2 Public Struct and returns it as a crypto.PublicKey,
func ParsePublicKey(contents *tpm2.TPMTPublic) (crypto.PublicKey, error) {
	var pubKey crypto.PublicKey
	switch contents.Type {
	case tpm2.TPMAlgRSA:
		details, err := contents.Parameters.RSADetail()
		if err != nil {
			return nil, fmt.Errorf("failed to read RSA details: %w", err)
		}
		unique, err := contents.Unique.RSA()
		if err != nil {
			return nil, fmt.Errorf("failed to read RSA unique: %w", err)
		}
		pubKey, err = tpm2.RSAPub(details, unique)
		if err != nil {
			return nil, fmt.Errorf("failed to create RSA public key: %w", err)
		}
	case tpm2.TPMAlgECC:
		details, err := contents.Parameters.ECCDetail()
		if err != nil {
			return nil, fmt.Errorf("failed to read ECC details: %w", err)
		}
		curve, err := details.CurveID.Curve()
		if err != nil {
			return nil, fmt.Errorf("failed to get curve: %w", err)
		}
		unique, err := contents.Unique.ECC()
		if err != nil {
			return nil, fmt.Errorf("failed to read ECC unique: %w", err)
		}
		pubKey = &ecdsa.PublicKey{
			Curve: curve,
			X:     big.NewInt(0).SetBytes(unique.X.Buffer),
			Y:     big.NewInt(0).SetBytes(unique.Y.Buffer),
		}
	default:
		return nil, fmt.Errorf("unsupported key type %v", contents.Type)
	}
	return pubKey, nil
}

func pcrPolicyCallback(tpm *TPM, pcrs []uint) tpm2.PolicyCallback {
	return func(t transport.TPM, handle tpm2.TPMISHPolicy, _ tpm2.TPM2BNonce) error {
		pcrSelection := tpm.SelectPCRs(pcrs...)
		_, err := tpm2.PolicyPCR{
			PolicySession: handle,
			PcrDigest:     tpm2.TPM2BDigest{},
			Pcrs:          pcrSelection,
		}.Execute(t)
		return err
	}
}
