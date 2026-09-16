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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseEKCertificateAcceptsSTNonMinimalSerial(t *testing.T) {
	certDER := createTestEKCertificate(t, STMicroelectronicsIssuerOrganization)
	malformedDER := addRedundantSerialZero(t, certDER)
	certBytes := append(bytes.Clone(malformedDER), bytes.Repeat([]byte{0xff}, 32)...)

	_, err := x509.ParseCertificate(malformedDER)
	assert.Error(t, err)

	var outer, tbs asn1.RawValue
	_, err = asn1.Unmarshal(malformedDER, &outer)
	require.NoError(t, err)
	_, err = asn1.Unmarshal(outer.Bytes, &tbs)
	require.NoError(t, err)

	cert, err := ParseEKCertificate(certBytes)
	require.NoError(t, err)
	assert.Equal(t, malformedDER, cert.Raw)
	assert.Equal(t, big.NewInt(0x2676), cert.SerialNumber)
	assert.Equal(t, tbs.FullBytes, cert.RawTBSCertificate)
	assert.Equal(t, []string{STMicroelectronicsIssuerOrganization}, cert.Issuer.Organization)
	assert.NotContains(t, cert.Subject.Organization, STMicroelectronicsIssuerOrganization)
}

func TestParseEKCertificateAcceptsMultipleRedundantSerialZeros(t *testing.T) {
	certDER := createTestEKCertificate(t, STMicroelectronicsIssuerOrganization)
	malformedDER := addRedundantSerialZeros(t, certDER, 2)

	cert, err := ParseEKCertificate(malformedDER)
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(0x2676), cert.SerialNumber)
}

func TestParseEKCertificateKeepsValidCertificate(t *testing.T) {
	certDER := createTestEKCertificate(t, STMicroelectronicsIssuerOrganization)

	cert, err := ParseEKCertificate(certDER)
	require.NoError(t, err)
	assert.Equal(t, certDER, cert.Raw)
}

func TestParseEKCertificateHandlesTCGNVWrapper(t *testing.T) {
	certDER := createTestEKCertificate(t, STMicroelectronicsIssuerOrganization)
	malformedDER := addRedundantSerialZero(t, certDER)
	wrappedDER := wrapTCGNVCertificate(t, malformedDER, len(malformedDER))

	tests := []struct {
		name             string
		certBytes        []byte
		wantErrorContain string
	}{
		{
			name:      "certificate",
			certBytes: wrappedDER,
		},
		{
			name:      "trailing bytes",
			certBytes: append(bytes.Clone(wrappedDER), bytes.Repeat([]byte{0xff}, 32)...),
		},
		{
			name:             "zero certificate length",
			certBytes:        wrapTCGNVCertificate(t, nil, 0),
			wantErrorContain: "empty certificate",
		},
		{
			name:             "truncated certificate",
			certBytes:        wrapTCGNVCertificate(t, malformedDER[:len(malformedDER)-1], len(malformedDER)),
			wantErrorContain: "with only",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cert, err := ParseEKCertificate(test.certBytes)
			if test.wantErrorContain != "" {
				require.ErrorContains(t, err, test.wantErrorContain)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, malformedDER, cert.Raw)
		})
	}
}

func TestParseEKCertificateRejectsNonMinimalSerialFromUnknownIssuer(t *testing.T) {
	certDER := createTestEKCertificate(t, "Other TPM Vendor")
	malformedDER := addRedundantSerialZero(t, certDER)

	_, err := ParseEKCertificate(malformedDER)
	require.Error(t, err)
	assert.ErrorContains(t, err, "issuer organizations")
}

func TestParseEKCertificateReportsFallbackFailures(t *testing.T) {
	t.Run("DER extraction", func(t *testing.T) {
		_, err := ParseEKCertificate([]byte{0x30, 0x01})
		require.Error(t, err)
		assert.ErrorContains(t, err, "extracting certificate DER")
	})

	t.Run("no redundant serial padding", func(t *testing.T) {
		certDER := createIncompleteTestCertificate(t, []byte{0x01})

		_, err := ParseEKCertificate(certDER)
		require.ErrorContains(t, err, "serial number has no redundant leading zero padding")
	})

	t.Run("normalized certificate parsing", func(t *testing.T) {
		certDER := createIncompleteTestCertificate(t, []byte{0x00, 0x01})

		_, err := ParseEKCertificate(certDER)
		require.Error(t, err)
		assert.ErrorContains(t, err, "parsing normalized certificate")
	})
}

func createTestEKCertificate(t *testing.T, issuerOrganization string) []byte {
	t.Helper()
	subjectKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(0x2676),
		Subject: pkix.Name{
			Organization: []string{"Test EK Device"},
		},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(3600, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	issuer := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{issuerOrganization},
		},
		NotBefore:             template.NotBefore,
		NotAfter:              template.NotAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, issuer, &subjectKey.PublicKey, issuerKey)
	require.NoError(t, err)
	return certDER
}

func wrapTCGNVCertificate(t *testing.T, certBytes []byte, certLen int) []byte {
	t.Helper()
	if certLen < 0 || certLen > math.MaxUint16 {
		t.Fatalf("certificate length %d does not fit in a TCG NV wrapper", certLen)
	}
	wrapped := make([]byte, 5, 5+len(certBytes))
	copy(wrapped, []byte{0x10, 0x01, 0x00})
	// #nosec G115 -- the bounds check above proves certLen fits in uint16.
	binary.BigEndian.PutUint16(wrapped[3:5], uint16(certLen))
	return append(wrapped, certBytes...)
}

func createIncompleteTestCertificate(t *testing.T, serialBytes []byte) []byte {
	t.Helper()
	serial, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagInteger,
		Bytes: serialBytes,
	})
	require.NoError(t, err)
	tbs, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      serial,
	})
	require.NoError(t, err)
	cert, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      tbs,
	})
	require.NoError(t, err)
	return cert
}

func addRedundantSerialZero(t *testing.T, certDER []byte) []byte {
	t.Helper()
	return addRedundantSerialZeros(t, certDER, 1)
}

func addRedundantSerialZeros(t *testing.T, certDER []byte, count int) []byte {
	t.Helper()
	var cert, tbs, version, serial asn1.RawValue
	remaining, err := asn1.Unmarshal(certDER, &cert)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	tbsRemainder, err := asn1.Unmarshal(cert.Bytes, &tbs)
	if err != nil {
		t.Fatalf("failed to parse TBSCertificate: %v", err)
	}
	serialInput, err := asn1.Unmarshal(tbs.Bytes, &version)
	if err != nil || version.Class != asn1.ClassContextSpecific || version.Tag != 0 {
		t.Fatalf("failed to parse certificate version: %v", err)
	}
	serialRemainder, err := asn1.Unmarshal(serialInput, &serial)
	if err != nil || serial.Tag != asn1.TagInteger || len(serial.Bytes) == 0 || serial.Bytes[0]&0x80 != 0 {
		t.Fatalf("failed to find a serial suitable for mutation: %v", err)
	}

	malformedSerial, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagInteger,
		Bytes: append(bytes.Repeat([]byte{0}, count), serial.Bytes...),
	})
	if err != nil {
		t.Fatal(err)
	}
	malformedTBSBody := make([]byte, 0, len(tbs.Bytes)+count)
	malformedTBSBody = append(malformedTBSBody, version.FullBytes...)
	malformedTBSBody = append(malformedTBSBody, malformedSerial...)
	malformedTBSBody = append(malformedTBSBody, serialRemainder...)
	malformedTBS, err := asn1.Marshal(asn1.RawValue{
		Class:      tbs.Class,
		Tag:        tbs.Tag,
		IsCompound: tbs.IsCompound,
		Bytes:      malformedTBSBody,
	})
	if err != nil {
		t.Fatal(err)
	}
	malformedCertBody := make([]byte, 0, len(cert.Bytes)+count)
	malformedCertBody = append(malformedCertBody, malformedTBS...)
	malformedCertBody = append(malformedCertBody, tbsRemainder...)
	malformedCert, err := asn1.Marshal(asn1.RawValue{
		Class:      cert.Class,
		Tag:        cert.Tag,
		IsCompound: cert.IsCompound,
		Bytes:      malformedCertBody,
	})
	if err != nil {
		t.Fatal(err)
	}
	return malformedCert
}
