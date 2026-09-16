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
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"slices"

	attestHelper "github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpm2"
)

const STMicroelectronicsIssuerOrganization = "STMicroelectronics NV"

// IsSTMicroelectronicsEKCertificate reports whether the parsed issuer claims to
// be STMicroelectronics. This is only a parsing heuristic, so callers must
// still validate the certificate chain.
func IsSTMicroelectronicsEKCertificate(cert *x509.Certificate) bool {
	return cert != nil && slices.Contains(cert.Issuer.Organization, STMicroelectronicsIssuerOrganization)
}

// GetEKCert reads the EK certificate from NV storage.
func (tpm *TPM) GetEKCert(certIndex tpm2.TPMHandle, password string) (*x509.Certificate, error) {
	certBytes, err := tpm.ReadFromNVStorage(certIndex, password)
	if err != nil {
		return nil, fmt.Errorf("failed to read EK certificate from NV storage: %w", err)
	}
	return ParseEKCertificate(certBytes)
}

// ParseEKCertificate parses an EK certificate, tolerating malformed STM serials.
func ParseEKCertificate(certBytes []byte) (*x509.Certificate, error) {
	cert, parseErr := attestHelper.ParseEKCertificate(certBytes)
	if parseErr == nil {
		return cert, nil
	}

	certDER, err := extractEKCertificateDER(certBytes)
	if err != nil {
		return nil, newEKCertificateFallbackError(parseErr, fmt.Errorf("extracting certificate DER: %w", err))
	}
	normalizedDER, originalTBS, err := stripSerialNumberLeadingNullBytes(certDER)
	if err != nil {
		return nil, newEKCertificateFallbackError(parseErr, fmt.Errorf("normalizing serial number: %w", err))
	}
	cert, err = x509.ParseCertificate(normalizedDER)
	if err != nil {
		return nil, newEKCertificateFallbackError(parseErr, fmt.Errorf("parsing normalized certificate: %w", err))
	}

	// The malformed serial prevents x509 from reading the issuer, so gate the
	// compatibility path immediately after parsing the normalized certificate.
	if !IsSTMicroelectronicsEKCertificate(cert) {
		return nil, newEKCertificateFallbackError(
			parseErr,
			fmt.Errorf(
				"issuer organizations %q do not include %q, not valid for fallback parsing",
				cert.Issuer.Organization,
				STMicroelectronicsIssuerOrganization,
			),
		)
	}

	// Retain the original certificate and signed TBS; parsed fields use normalized DER.
	cert.Raw = certDER
	cert.RawTBSCertificate = originalTBS
	return cert, nil
}

func newEKCertificateFallbackError(parseErr, fallbackErr error) error {
	return fmt.Errorf(
		"failed to parse EK certificate: %w; STMicroelectronics serial normalization fallback failed: %w",
		parseErr,
		fallbackErr,
	)
}

// extractEKCertificateDER extracts the first DER-encoded certificate from an
// optional TCG NV wrapper, ignoring any unused bytes after the certificate.
func extractEKCertificateDER(certBytes []byte) ([]byte, error) {
	// These bytes as a legacy TPM 1.2 PC Client NVRAM wrapper marker;
	// the next two bytes contain the big-endian certificate length.
	if len(certBytes) >= 5 && bytes.Equal(certBytes[:3], []byte{0x10, 0x01, 0x00}) {
		certLen := int(binary.BigEndian.Uint16(certBytes[3:5]))
		if certLen == 0 {
			return nil, fmt.Errorf("TCG NV wrapper contains an empty certificate")
		}
		if len(certBytes) < certLen+5 {
			return nil, fmt.Errorf(
				"TCG NV wrapper declares certificate length %d with only %d bytes available",
				certLen,
				len(certBytes)-5,
			)
		}
		certBytes = certBytes[5 : 5+certLen]
	}

	var cert asn1.RawValue
	if _, err := asn1.Unmarshal(certBytes, &cert); err != nil {
		return nil, fmt.Errorf("unmarshalling certificate DER: %w", err)
	}
	if cert.Class != asn1.ClassUniversal || cert.Tag != asn1.TagSequence || !cert.IsCompound {
		return nil, fmt.Errorf("certificate is not a compound ASN.1 SEQUENCE")
	}
	return bytes.Clone(cert.FullBytes), nil
}

// stripSerialNumberLeadingNullBytes removes redundant serial-number padding for strict
// DER parsing while preserving the original TBS bytes for signature verification.
func stripSerialNumberLeadingNullBytes(certDER []byte) ([]byte, []byte, error) {
	var cert, tbs, firstField, serial asn1.RawValue
	remaining, err := asn1.Unmarshal(certDER, &cert)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshalling certificate: %w", err)
	}
	if len(remaining) != 0 {
		return nil, nil, fmt.Errorf("certificate contains trailing data")
	}
	if cert.Class != asn1.ClassUniversal || cert.Tag != asn1.TagSequence || !cert.IsCompound {
		return nil, nil, fmt.Errorf("certificate is not a compound ASN.1 SEQUENCE")
	}
	tbsRemainder, err := asn1.Unmarshal(cert.Bytes, &tbs)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshalling TBSCertificate: %w", err)
	}
	if tbs.Class != asn1.ClassUniversal || tbs.Tag != asn1.TagSequence || !tbs.IsCompound {
		return nil, nil, fmt.Errorf("TBSCertificate is not a compound ASN.1 SEQUENCE")
	}

	fieldRemainder, err := asn1.Unmarshal(tbs.Bytes, &firstField)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshalling first TBSCertificate field: %w", err)
	}
	serialOffset := 0
	serialRemainder := fieldRemainder
	// Version is an optional field; advance to the serial number when present.
	if firstField.Class == asn1.ClassContextSpecific && firstField.Tag == 0 {
		serialOffset = len(tbs.Bytes) - len(fieldRemainder)
		serialRemainder, err = asn1.Unmarshal(fieldRemainder, &serial)
		if err != nil {
			return nil, nil, fmt.Errorf("unmarshalling certificate serial number: %w", err)
		}
	} else {
		serial = firstField
	}
	if serial.Class != asn1.ClassUniversal || serial.Tag != asn1.TagInteger || serial.IsCompound {
		return nil, nil, fmt.Errorf("certificate serial number is not a primitive ASN.1 INTEGER")
	}
	normalizedSerialBytes := serial.Bytes
	for len(normalizedSerialBytes) > 1 && normalizedSerialBytes[0] == 0 && normalizedSerialBytes[1]&0x80 == 0 {
		normalizedSerialBytes = normalizedSerialBytes[1:]
	}
	removedBytes := len(serial.Bytes) - len(normalizedSerialBytes)
	if removedBytes == 0 {
		return nil, nil, fmt.Errorf("serial number has no redundant leading zero padding")
	}

	normalizedSerial, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagInteger,
		Bytes: normalizedSerialBytes,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("marshalling normalized serial number: %w", err)
	}
	normalizedTBSBody := make([]byte, 0, len(tbs.Bytes)-removedBytes)
	normalizedTBSBody = append(normalizedTBSBody, tbs.Bytes[:serialOffset]...)
	normalizedTBSBody = append(normalizedTBSBody, normalizedSerial...)
	normalizedTBSBody = append(normalizedTBSBody, serialRemainder...)
	normalizedTBS, err := asn1.Marshal(asn1.RawValue{
		Class:      tbs.Class,
		Tag:        tbs.Tag,
		IsCompound: tbs.IsCompound,
		Bytes:      normalizedTBSBody,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("marshalling normalized TBSCertificate: %w", err)
	}
	normalizedCertBody := make([]byte, 0, len(cert.Bytes)-removedBytes)
	normalizedCertBody = append(normalizedCertBody, normalizedTBS...)
	normalizedCertBody = append(normalizedCertBody, tbsRemainder...)
	normalizedCert, err := asn1.Marshal(asn1.RawValue{
		Class:      cert.Class,
		Tag:        cert.Tag,
		IsCompound: cert.IsCompound,
		Bytes:      normalizedCertBody,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("marshalling normalized certificate: %w", err)
	}
	return normalizedCert, bytes.Clone(tbs.FullBytes), nil
}
