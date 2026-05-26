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

/*
This was copied from go-tpm/tpm2/errors.go file.
*/

const (
	rcVer1 = 0x00000100
	rcFmt1 = 0x00000080
	rcWarn = 0x00000900
	rcP    = 0x00000040
	rcS    = 0x00000800
)

type errorDesc struct {
	name        string
	description string
}

var fmt0Descs = map[tpm2.TPMRC]errorDesc{
	tpm2.TPMRCInitialize: {
		name:        "TPM_RC_INITIALIZE",
		description: "TPM not initialized by TPM2_Startup or already initialized",
	},
	tpm2.TPMRCFailure: {
		name:        "TPM_RC_FAILURE",
		description: "commands not being accepted because of a TPM failure",
	},
	tpm2.TPMRCSequence: {
		name:        "TPM_RC_SEQUENCE",
		description: "improper use of a sequence handle",
	},
	tpm2.TPMRCPrivate: {
		name:        "TPM_RC_PRIVATE",
		description: "not currently used",
	},
	tpm2.TPMRCHMAC: {
		name:        "TPM_RC_HMAC",
		description: "not currently used",
	},
	tpm2.TPMRCDisabled: {
		name:        "TPM_RC_DISABLED",
		description: "the command is disabled",
	},
	tpm2.TPMRCExclusive: {
		name:        "TPM_RC_EXCLUSIVE",
		description: "command failed because audit sequence required exclusivity",
	},
	tpm2.TPMRCAuthType: {
		name:        "TPM_RC_AUTH_TYPE",
		description: "authorization handle is not correct for command",
	},
	tpm2.TPMRCAuthMissing: {
		name:        "TPM_RC_AUTH_MISSING",
		description: "command requires an authorization session for handle and it is not present.",
	},
	tpm2.TPMRCPolicy: {
		name:        "TPM_RC_POLICY",
		description: "policy failure in math operation or an invalid authPolicy value",
	},
	tpm2.TPMRCPCR: {
		name:        "TPM_RC_PCR",
		description: "PCR check fail",
	},
	tpm2.TPMRCPCRChanged: {
		name:        "TPM_RC_PCR_CHANGED",
		description: "PCR have changed since checked.",
	},
	tpm2.TPMRCUpgrade: {
		name:        "TPM_RC_UPGRADE",
		description: "for all commands other than TPM2_FieldUpgradeData(), this code indicates that the TPM is in field upgrade mode; for TPM2_FieldUpgradeData(), this code indicates that the TPM is not in field upgrade mode",
	},
	tpm2.TPMRCTooManyContexts: {
		name:        "TPM_RC_TOO_MANY_CONTEXTS",
		description: "context ID counter is at maximum.",
	},
	tpm2.TPMRCAuthUnavailable: {
		name:        "TPM_RC_AUTH_UNAVAILABLE",
		description: "authValue or authPolicy is not available for selected entity.",
	},
	tpm2.TPMRCReboot: {
		name:        "TPM_RC_REBOOT",
		description: "a _TPM_Init and Startup(CLEAR) is required before the TPM can resume operation.",
	},
	tpm2.TPMRCUnbalanced: {
		name:        "TPM_RC_UNBALANCED",
		description: "the protection algorithms (hash and symmetric) are not reasonably balanced. The digest size of the hash must be larger than the key size of the symmetric algorithm.",
	},
	tpm2.TPMRCCommandSize: {
		name:        "TPM_RC_COMMAND_SIZE",
		description: "command commandSize value is inconsistent with contents of the command buffer; either the size is not the same as the octets loaded by the hardware interface layer or the value is not large enough to hold a command header",
	},
	tpm2.TPMRCCommandCode: {
		name:        "TPM_RC_COMMAND_CODE",
		description: "command code not supported",
	},
	tpm2.TPMRCAuthSize: {
		name:        "TPM_RC_AUTHSIZE",
		description: "the value of authorizationSize is out of range or the number of octets in the Authorization Area is greater than required",
	},
	tpm2.TPMRCAuthContext: {
		name:        "TPM_RC_AUTH_CONTEXT",
		description: "use of an authorization session with a context command or another command that cannot have an authorization session.",
	},
	tpm2.TPMRCNVRange: {
		name:        "TPM_RC_NV_RANGE",
		description: "NV offset+size is out of range.",
	},
	tpm2.TPMRCNVSize: {
		name:        "TPM_RC_NV_SIZE",
		description: "Requested allocation size is larger than allowed.",
	},
	tpm2.TPMRCNVLocked: {
		name:        "TPM_RC_NV_LOCKED",
		description: "NV access locked.",
	},
	tpm2.TPMRCNVAuthorization: {
		name:        "TPM_RC_NV_AUTHORIZATION",
		description: "NV access authorization fails in command actions (this failure does not affect lockout.action)",
	},
	tpm2.TPMRCNVUninitialized: {
		name:        "TPM_RC_NV_UNINITIALIZED",
		description: "an NV Index is used before being initialized or the state saved by TPM2_Shutdown(STATE) could not be restored",
	},
	tpm2.TPMRCNVSpace: {
		name:        "TPM_RC_NV_SPACE",
		description: "insufficient space for NV allocation",
	},
	tpm2.TPMRCNVDefined: {
		name:        "TPM_RC_NV_DEFINED",
		description: "NV Index or persistent object already defined",
	},
	tpm2.TPMRCBadContext: {
		name:        "TPM_RC_BAD_CONTEXT",
		description: "context in TPM2_ContextLoad() is not valid",
	},
	tpm2.TPMRCCPHash: {
		name:        "TPM_RC_CPHASH",
		description: "cpHash value already set or not correct for use",
	},
	tpm2.TPMRCParent: {
		name:        "TPM_RC_PARENT",
		description: "handle for parent is not a valid parent",
	},
	tpm2.TPMRCNeedsTest: {
		name:        "TPM_RC_NEEDS_TEST",
		description: "some function needs testing.",
	},
	tpm2.TPMRCNoResult: {
		name:        "TPM_RC_NO_RESULT",
		description: "an internal function cannot process a request due to an unspecified problem. This code is usually related to invalid parameters that are not properly filtered by the input unmarshaling code.",
	},
	tpm2.TPMRCSensitive: {
		name:        "TPM_RC_SENSITIVE",
		description: "the sensitive area did not unmarshal correctly after decryption – this code is used in lieu of the other unmarshaling errors so that an attacker cannot determine where the unmarshaling error occurred",
	},
}

var fmt1Descs = map[tpm2.TPMRC]errorDesc{
	tpm2.TPMRCAsymmetric: {
		name:        "TPM_RC_ASYMMETRIC",
		description: "asymmetric algorithm not supported or not correct",
	},
	tpm2.TPMRCAttributes: {
		name:        "TPM_RC_ATTRIBUTES",
		description: "inconsistent attributes",
	},
	tpm2.TPMRCHash: {
		name:        "TPM_RC_HASH",
		description: "hash algorithm not supported or not appropriate",
	},
	tpm2.TPMRCValue: {
		name:        "TPM_RC_VALUE",
		description: "value is out of range or is not correct for the context",
	},
	tpm2.TPMRCHierarchy: {
		name:        "TPM_RC_HIERARCHY",
		description: "hierarchy is not enabled or is not correct for the use",
	},
	tpm2.TPMRCKeySize: {
		name:        "TPM_RC_KEY_SIZE",
		description: "key size is not supported",
	},
	tpm2.TPMRCMGF: {
		name:        "TPM_RC_MGF",
		description: "mask generation function not supported",
	},
	tpm2.TPMRCMode: {
		name:        "TPM_RC_MODE",
		description: "mode of operation not supported",
	},
	tpm2.TPMRCType: {
		name:        "TPM_RC_TYPE",
		description: "the type of the value is not appropriate for the use",
	},
	tpm2.TPMRCHandle: {
		name:        "TPM_RC_HANDLE",
		description: "the handle is not correct for the use",
	},
	tpm2.TPMRCKDF: {
		name:        "TPM_RC_KDF",
		description: "unsupported key derivation function or function not appropriate for use",
	},
	tpm2.TPMRCRange: {
		name:        "TPM_RC_RANGE",
		description: "value was out of allowed range.",
	},
	tpm2.TPMRCAuthFail: {
		name:        "TPM_RC_AUTH_FAIL",
		description: "the authorization HMAC check failed and DA counter incremented",
	},
	tpm2.TPMRCNonce: {
		name:        "TPM_RC_NONCE",
		description: "invalid nonce size or nonce value mismatch",
	},
	tpm2.TPMRCPP: {
		name:        "TPM_RC_PP",
		description: "authorization requires assertion of PP",
	},
	tpm2.TPMRCScheme: {
		name:        "TPM_RC_SCHEME",
		description: "unsupported or incompatible scheme",
	},
	tpm2.TPMRCSize: {
		name:        "TPM_RC_SIZE",
		description: "structure is the wrong size",
	},
	tpm2.TPMRCSymmetric: {
		name:        "TPM_RC_SYMMETRIC",
		description: "unsupported symmetric algorithm or key size, or not appropriate for instance",
	},
	tpm2.TPMRCTag: {
		name:        "TPM_RC_TAG",
		description: "incorrect structure tag",
	},
	tpm2.TPMRCSelector: {
		name:        "TPM_RC_SELECTOR",
		description: "union selector is incorrect",
	},
	tpm2.TPMRCInsufficient: {
		name:        "TPM_RC_INSUFFICIENT",
		description: "the TPM was unable to unmarshal a value because there were not enough octets in the input buffer",
	},
	tpm2.TPMRCSignature: {
		name:        "TPM_RC_SIGNATURE",
		description: "the signature is not valid",
	},
	tpm2.TPMRCKey: {
		name:        "TPM_RC_KEY",
		description: "key fields are not compatible with the selected use",
	},
	tpm2.TPMRCPolicyFail: {
		name:        "TPM_RC_POLICY_FAIL",
		description: "a policy check failed",
	},
	tpm2.TPMRCIntegrity: {
		name:        "TPM_RC_INTEGRITY",
		description: "integrity check failed",
	},
	tpm2.TPMRCTicket: {
		name:        "TPM_RC_TICKET",
		description: "invalid ticket",
	},
	tpm2.TPMRCReservedBits: {
		name:        "TPM_RC_RESERVED_BITS",
		description: "reserved bits not set to zero as required",
	},
	tpm2.TPMRCBadAuth: {
		name:        "TPM_RC_BAD_AUTH",
		description: "authorization failure without DA implications",
	},
	tpm2.TPMRCExpired: {
		name:        "TPM_RC_EXPIRED",
		description: "the policy has expired",
	},
	tpm2.TPMRCPolicyCC: {
		name:        "TPM_RC_POLICY_CC",
		description: "the commandCode in the policy is not the commandCode of the command or the command code in a policy command references a command that is not implemented",
	},
	tpm2.TPMRCBinding: {
		name:        "TPM_RC_BINDING",
		description: "public and sensitive portions of an object are not cryptographically bound",
	},
	tpm2.TPMRCCurve: {
		name:        "TPM_RC_CURVE",
		description: "curve not supported",
	},
	tpm2.TPMRCECCPoint: {
		name:        "TPM_RC_ECC_POINT",
		description: "point is not on the required curve.",
	},
}

var warnDescs = map[tpm2.TPMRC]errorDesc{
	tpm2.TPMRCContextGap: {
		name:        "TPM_RC_CONTEXT_GAP",
		description: "gap for context ID is too large",
	},
	tpm2.TPMRCObjectMemory: {
		name:        "TPM_RC_OBJECT_MEMORY",
		description: "out of memory for object contexts",
	},
	tpm2.TPMRCSessionMemory: {
		name:        "TPM_RC_SESSION_MEMORY",
		description: "out of memory for session contexts",
	},
	tpm2.TPMRCMemory: {
		name:        "TPM_RC_MEMORY",
		description: "out of shared object/session memory or need space for internal operations",
	},
	tpm2.TPMRCSessionHandles: {
		name:        "TPM_RC_SESSION_HANDLES",
		description: "out of session handles – a session must be flushed before a new session may be created",
	},
	tpm2.TPMRCObjectHandles: {
		name:        "TPM_RC_OBJECT_HANDLES",
		description: "out of object handles – the handle space for objects is depleted and a reboot is required",
	},
	tpm2.TPMRCLocality: {
		name:        "TPM_RC_LOCALITY",
		description: "bad locality",
	},
	tpm2.TPMRCYielded: {
		name:        "TPM_RC_YIELDED",
		description: "the TPM has suspended operation on the command; forward progress was made and the command may be retried",
	},
	tpm2.TPMRCCanceled: {
		name:        "TPM_RC_CANCELED",
		description: "the command was canceled",
	},
	tpm2.TPMRCTesting: {
		name:        "TPM_RC_TESTING",
		description: "TPM is performing self-tests",
	},
	tpm2.TPMRCReferenceH0: {
		name:        "TPM_RC_REFERENCE_H0",
		description: "the 1st handle in the handle area references a transient object or session that is not loaded",
	},
	tpm2.TPMRCReferenceH1: {
		name:        "TPM_RC_REFERENCE_H1",
		description: "the 2nd handle in the handle area references a transient object or session that is not loaded",
	},
	tpm2.TPMRCReferenceH2: {
		name:        "TPM_RC_REFERENCE_H2",
		description: "the 3rd handle in the handle area references a transient object or session that is not loaded",
	},
	tpm2.TPMRCReferenceH3: {
		name:        "TPM_RC_REFERENCE_H3",
		description: "the 4th handle in the handle area references a transient object or session that is not loaded",
	},
	tpm2.TPMRCReferenceH4: {
		name:        "TPM_RC_REFERENCE_H4",
		description: "the 5th handle in the handle area references a transient object or session that is not loaded",
	},
	tpm2.TPMRCReferenceH5: {
		name:        "TPM_RC_REFERENCE_H5",
		description: "the 6th handle in the handle area references a transient object or session that is not loaded",
	},
	tpm2.TPMRCReferenceH6: {
		name:        "TPM_RC_REFERENCE_H6",
		description: "the 7th handle in the handle area references a transient object or session that is not loaded",
	},
	tpm2.TPMRCReferenceS0: {
		name:        "TPM_RC_REFERENCE_S0",
		description: "the 1st authorization session handle references a session that is not loaded",
	},
	tpm2.TPMRCReferenceS1: {
		name:        "TPM_RC_REFERENCE_S1",
		description: "the 2nd authorization session handle references a session that is not loaded",
	},
	tpm2.TPMRCReferenceS2: {
		name:        "TPM_RC_REFERENCE_S2",
		description: "the 3rd authorization session handle references a session that is not loaded",
	},
	tpm2.TPMRCReferenceS3: {
		name:        "TPM_RC_REFERENCE_S3",
		description: "the 4th authorization session handle references a session that is not loaded",
	},
	tpm2.TPMRCReferenceS4: {
		name:        "TPM_RC_REFERENCE_S4",
		description: "the 5th session handle references a session that is not loaded",
	},
	tpm2.TPMRCReferenceS5: {
		name:        "TPM_RC_REFERENCE_S5",
		description: "the 6th session handle references a session that is not loaded",
	},
	tpm2.TPMRCReferenceS6: {
		name:        "TPM_RC_REFERENCE_S6",
		description: "the 7th authorization session handle references a session that is not loaded",
	},
	tpm2.TPMRCNVRate: {
		name:        "TPM_RC_NV_RATE",
		description: "the TPM is rate-limiting accesses to prevent wearout of NV",
	},
	tpm2.TPMRCLockout: {
		name:        "TPM_RC_LOCKOUT",
		description: "authorizations for objects subject to DA protection are not allowed at this time because the TPM is in DA lockout mode",
	},
	tpm2.TPMRCRetry: {
		name:        "TPM_RC_RETRY",
		description: "the TPM was not able to start the command",
	},
	tpm2.TPMRCNVUnavailable: {
		name:        "TPM_RC_NV_UNAVAILABLE",
		description: "the command may require writing of NV and NV is not current accessible",
	},
}

// isFmt0Error returns true if the result is a format-0 error.
func isFmt0Error(r tpm2.TPMRC) bool {
	return (uint32(r)&rcVer1) == rcVer1 && (uint32(r)&rcWarn) != rcWarn
}

// isFmt1Error returns true and a format-1 error structure if the error is a
// format-1 error.
func isFmt1Error(r tpm2.TPMRC) (bool, uint32) {
	if (r & rcFmt1) != rcFmt1 {
		return false, 0
	}
	if (r & rcP) == rcP {
		r ^= rcP
	} else if (r & rcS) == rcS {
		r ^= rcS
	}
	r &= 0xFFFFF0FF
	// return canonical response code
	return true, uint32(r)
}

// IsWarning returns true if the error is a warning code.
// This usually indicates a problem with the TPM state, and not the command.
// Retrying the command later may succeed.
func IsWarning(rc tpm2.TPMRC) bool {
	if isFmt1, _ := isFmt1Error(rc); isFmt1 {
		// There aren't any format-1 warnings.
		return false
	}
	return (uint32(rc)&rcVer1) == rcVer1 && (rc&rcWarn) == rcWarn
}

// ToErrorType returns the type of the error.
func ToErrorType(rc tpm2.TPMRC) (_errorType ErrorType) {
	var (
		desc errorDesc
		ok   bool
	)
	defer func() {
		if ok {
			_errorType = ErrorType(desc.name)
			return
		}
		_errorType = OtherErrType
	}()

	if isFmt1, fmt1rc := isFmt1Error(rc); isFmt1 {
		desc, ok = fmt1Descs[tpm2.TPMRC(fmt1rc)]
	} else if isFmt0Error(rc) {
		desc, ok = fmt0Descs[rc]
	} else if IsWarning(rc) {
		desc, ok = warnDescs[rc]
	}
	return
}
