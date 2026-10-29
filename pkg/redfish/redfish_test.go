// Copyright (c) Meta Platforms, Inc. and affiliates.
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

package redfish

import (
	"cmp"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testMAC is a documentation-range address (RFC 7042).
const testMAC = "00:00:5e:00:53:10"

// fakeBMC serves the Redfish routes the component-integrity join needs. A TargetComponentURI
// naming a nonexistent adapter gets a 200 and an unquoted schema stub rather than a 404, so it
// fails to decode.
func fakeBMC(t *testing.T, targetURI string) *httptest.Server {
	t.Helper()
	return fakeBMCWithSPDM(t, targetURI, "")
}

// fakeBMCWithSPDM is fakeBMC with a measurement set on the SPDM component.
func fakeBMCWithSPDM(t *testing.T, targetURI, spdm string) *httptest.Server {
	t.Helper()
	server, _ := serveRoutes(t, bmcRoutes(targetURI, spdm))
	return server
}

// serveRoutes answers each path in routes with its body and anything else with a 404, and returns
// how many times a path was read.
func serveRoutes(t *testing.T, routes map[string]string) (*httptest.Server, func(path string) int) {
	t.Helper()
	var mu sync.Mutex
	reads := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reads[r.URL.Path]++
		mu.Unlock()
		body, ok := routes[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server, func(path string) int {
		mu.Lock()
		defer mu.Unlock()
		return reads[path]
	}
}

// bmcRoutes is a BMC with one SPDM NIC, behind targetURI, and its TPM.
func bmcRoutes(targetURI, spdm string) map[string]string {
	spdm = cmp.Or(spdm, `"SPDM":{}`)
	return map[string]string{
		"/redfish/v1/ComponentIntegrity": `{"Members":[
			{"@odata.id":"/redfish/v1/ComponentIntegrity/OCPSlot-022-00"},
			{"@odata.id":"/redfish/v1/ComponentIntegrity/TPM-1"}]}`,

		"/redfish/v1/ComponentIntegrity/OCPSlot-022-00": `{
			"Id":"OCPSlot-022-00","ComponentIntegrityType":"SPDM",` + spdm + `,
			"TargetComponentURI":"` + targetURI + `"}`,

		// The TPM shares the collection and must be skipped, not treated as a failure.
		"/redfish/v1/ComponentIntegrity/TPM-1": `{
			"Id":"TPM-1","ComponentIntegrityType":"TPM",
			"TargetComponentURI":"/redfish/v1/Managers/1",
			"Actions":{"#ComponentIntegrity.TPMGetSignedMeasurements":{
				"target":"/redfish/v1/ComponentIntegrity/TPM-1/Actions/ComponentIntegrity.TPMGetSignedMeasurements"}}}`,

		// Collections the client discovers through: the member names are vendor-chosen, so
		// nothing is assembled from a constant.
		"/redfish/v1/Managers": `{"Members":[{"@odata.id":"/redfish/v1/Managers/1"}]}`,
		"/redfish/v1/Systems":  `{"Members":[{"@odata.id":"/redfish/v1/Systems/1"}]}`,
		// HPE keeps the IDevID under an OEM path, so its standard collection does not list one.
		"/redfish/v1/Managers/1/Certificates": `{"Members":[]}`,

		"/redfish/v1/Chassis/1/NetworkAdapters": `{"Members":[
			{"@odata.id":"/redfish/v1/Chassis/1/NetworkAdapters/DA000000"}]}`,

		"/redfish/v1/Chassis/1/NetworkAdapters/DA000000": `{
			"Id":"DA000000","Model":"Example 100G NIC","SerialNumber":"SN0000000001",
			"Location":{"PartLocation":{"LocationType":"Slot","LocationOrdinalValue":22}},
			"Controllers":[{"FirmwarePackageVersion":"235.1.208.0"}],
			"Ports":{"@odata.id":"/redfish/v1/Chassis/1/NetworkAdapters/DA000000/Ports"}}`,

		"/redfish/v1/Chassis/1/NetworkAdapters/DA000000/Ports": `{"Members":[
			{"@odata.id":"/redfish/v1/Chassis/1/NetworkAdapters/DA000000/Ports/1"}]}`,

		"/redfish/v1/Chassis/1/NetworkAdapters/DA000000/Ports/1": `{
			"Ethernet":{"AssociatedMACAddresses":["` + testMAC + `"]}}`,

		// The stub the iLO serves for a nonexistent adapter.
		"/redfish/v1/Chassis/1/NetworkAdapters/00000000": "{\n  error:\n  {\n    code: string,\n    message: string\n  }\n}",
	}
}

// serveTPMDiscovery answers the reads quoteTarget makes, with TPM-1 covering the manager, and
// reports whether the request was one of them.
func serveTPMDiscovery(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/redfish/v1/Managers":
		_, _ = w.Write([]byte(`{"Members":[{"@odata.id":"/redfish/v1/Managers/1"}]}`))
	case "/redfish/v1/ComponentIntegrity":
		_, _ = w.Write([]byte(`{"Members":[{"@odata.id":"/redfish/v1/ComponentIntegrity/TPM-1"}]}`))
	case "/redfish/v1/ComponentIntegrity/TPM-1":
		_, _ = w.Write([]byte(`{"ComponentIntegrityType":"TPM","TargetComponentURI":"/redfish/v1/Managers/1",
			"Actions":{"#ComponentIntegrity.TPMGetSignedMeasurements":{"target":"/quote"}}}`))
	default:
		return false
	}
	return true
}

func clientFor(server *httptest.Server) *Client {
	return NewClient(server.URL, "user", "secret", server.Client())
}

// The slot the component is named for is the only join left when the target URI is a dead end.
func TestComponentIntegrityForFallsBackToSlotWhenTargetIsBogus(t *testing.T) {
	server := fakeBMC(t, "/redfish/v1/Chassis/1/NetworkAdapters/00000000")
	defer server.Close()

	ci, adapter, bmcMAC, err := clientFor(server).ComponentIntegrityFor(t.Context(), testMAC)
	require.NoError(t, err)
	assert.Equal(t, "OCPSlot-022-00", ci.ID)
	assert.Equal(t, "Example 100G NIC", adapter.Model)
	assert.Equal(t, testMAC, bmcMAC)
}

func TestComponentIntegrityForUsesTargetWhenItResolves(t *testing.T) {
	server := fakeBMC(t, "/redfish/v1/Chassis/1/NetworkAdapters/DA000000")
	defer server.Close()

	ci, adapter, bmcMAC, err := clientFor(server).ComponentIntegrityFor(t.Context(), testMAC)
	require.NoError(t, err)
	assert.Equal(t, "OCPSlot-022-00", ci.ID)
	assert.Equal(t, testMAC, bmcMAC)
	assert.Equal(t, 22, adapter.Location.PartLocation.LocationOrdinalValue)
}

// The MAC is the join: an unknown one must fail, not be handed whatever sits in the slot.
func TestComponentIntegrityForRejectsUnknownMAC(t *testing.T) {
	server := fakeBMC(t, "/redfish/v1/Chassis/1/NetworkAdapters/00000000")
	defer server.Close()

	_, _, _, err := clientFor(server).ComponentIntegrityFor(t.Context(), "aa:bb:cc:dd:ee:ff")
	require.ErrorContains(t, err, "no SPDM component on the BMC reports MAC")
}

// Echoing the caller's spelling would leave the verifier comparing a value with itself.
func TestComponentIntegrityForReturnsBMCSpellingOfMAC(t *testing.T) {
	server := fakeBMC(t, "/redfish/v1/Chassis/1/NetworkAdapters/00000000")
	defer server.Close()

	_, _, bmcMAC, err := clientFor(server).ComponentIntegrityFor(t.Context(), "00:00:5E:00:53:10")
	require.NoError(t, err)
	assert.Equal(t, testMAC, bmcMAC, "must be the BMC's spelling, not the caller's")
}

func TestComponentIntegrityForRejectsWhenNoSlotMatches(t *testing.T) {
	server := fakeBMC(t, "/redfish/v1/Chassis/1/NetworkAdapters/00000000")
	defer server.Close()

	client := clientFor(server)
	ci := &ComponentIntegrity{
		ID:                 "OCPSlot-099-00",
		Type:               "SPDM",
		TargetComponentURI: "/redfish/v1/Chassis/1/NetworkAdapters/00000000",
	}
	adapter, err := client.targetAdapter(t.Context(), ci)
	require.NoError(t, err, "every adapter read, so this is a definitive miss rather than unknown")
	assert.Nil(t, adapter, "slot 99 is not present and must not resolve to slot 22's adapter")
}

// A search truncated by a BMC that stopped answering must not read as "no component has this MAC".
func TestComponentIntegrityForDistinguishesAnUnreadableTargetFromAMiss(t *testing.T) {
	server := fakeBMC(t, "/redfish/v1/Chassis/1/NetworkAdapters/00000000")
	server.Close() // nothing will answer

	client := clientFor(server)
	ci := &ComponentIntegrity{
		ID:                 "NotSlotNamed",
		Type:               "SPDM",
		TargetComponentURI: "/redfish/v1/Chassis/1/NetworkAdapters/00000000",
	}
	adapter, err := client.targetAdapter(t.Context(), ci)
	assert.Nil(t, adapter)
	assert.Error(t, err, "an unreachable BMC is unknown, not a definitive non-adapter")
}

// A BMC can serve the leaf, intermediates and the root in one CertificateString. Returning the
// whole chain lets a verifier anchor on the root alone.
func TestIDevIDChainKeepsEveryCertificate(t *testing.T) {
	const chain = `-----BEGIN CERTIFICATE-----
MIIBAQ==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBAg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBAw==
-----END CERTIFICATE-----
`
	body, err := json.Marshal(map[string]string{"CertificateString": chain})
	require.NoError(t, err)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redfish/v1/Managers":
			_, _ = w.Write([]byte(`{"Members":[{"@odata.id":"/redfish/v1/Managers/1"}]}`))
		case "/redfish/v1/Managers/1/Certificates":
			_, _ = w.Write([]byte(`{"Members":[]}`))
		default:
			_, _ = w.Write(body)
		}
	}))
	defer server.Close()

	got, err := clientFor(server).IDevIDChain(t.Context())

	require.NoError(t, err)
	require.Len(t, got, 3, "leaf plus intermediates plus root")
	assert.Equal(t, []byte{0x30, 0x82, 0x01, 0x01}, got[0], "the leaf comes first")
}

// A Dell iDRAC: the manager and system members are named differently, the IDevID lives in the
// standard per-manager Certificates collection, and the ComponentIntegrity TPM member exposes no
// signed-measurement action. Nothing may be assembled from an HPE-shaped constant.
func TestClientWorksAgainstADellShapedBMC(t *testing.T) {
	routes := map[string]string{
		"/redfish/v1/Managers":                  `{"Members":[{"@odata.id":"/redfish/v1/Managers/iDRAC.Embedded.1"}]}`,
		"/redfish/v1/Systems":                   `{"Members":[{"@odata.id":"/redfish/v1/Systems/System.Embedded.1"}]}`,
		"/redfish/v1/Managers/iDRAC.Embedded.1": `{"Model":"17G Monolithic","FirmwareVersion":"1.30.30.52"}`,
		"/redfish/v1/Systems/System.Embedded.1": `{"Model":"PowerEdge","SKU":"ABC1234"}`,
		"/redfish/v1/Managers/iDRAC.Embedded.1/Certificates": `{"Members":[
			{"@odata.id":"/redfish/v1/Managers/iDRAC.Embedded.1/Certificates/iDEVID_ECC_NIST_P384"}]}`,
		"/redfish/v1/Managers/iDRAC.Embedded.1/Certificates/iDEVID_ECC_NIST_P384": `{
			"CertificateString":"-----BEGIN CERTIFICATE-----\nMIIBAA==\n-----END CERTIFICATE-----\n"}`,
		// HostTPM is the host's TPM, not the iDRAC's, and there is no TPM member for the iDRAC.
		"/redfish/v1/ComponentIntegrity": `{"Members":[
			{"@odata.id":"/redfish/v1/ComponentIntegrity/HostTPM"}]}`,
		"/redfish/v1/ComponentIntegrity/HostTPM": `{
			"Id":"HostTPM","ComponentIntegrityType":"TPM",
			"TargetComponentURI":"/redfish/v1/Systems/System.Embedded.1/","Actions":{"Oem":{}}}`,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	client := clientFor(server)

	manager, err := client.Manager(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "17G Monolithic", manager.Model, "resolved through the collection, not /Managers/1")

	system, err := client.System(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "PowerEdge", system.Model)

	chain, err := client.IDevIDChain(t.Context())
	require.NoError(t, err, "the IDevID is in the standard collection, not HPE's OEM path")
	require.Len(t, chain, 1)

	_, err = client.TPMSignedMeasurements(t.Context(), "00112233445566778899aabbccddeeff", "PCR0")
	assert.ErrorIs(t, err, ErrNoQuoteSupport, "no TPM of its own to quote, so the identity is all there is")
}

// A TPM member that covers the manager but advertises no action is a BMC that cannot quote.
func TestQuoteTargetReportsAManagerTPMWithoutAnAction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redfish/v1/ComponentIntegrity/TPM-1":
			_, _ = w.Write([]byte(`{"ComponentIntegrityType":"TPM","TargetComponentURI":"/redfish/v1/Managers/1"}`))
		default:
			if !serveTPMDiscovery(w, r) {
				http.NotFound(w, r)
			}
		}
	}))
	defer server.Close()

	_, err := clientFor(server).quoteTarget(t.Context())

	assert.ErrorIs(t, err, ErrNoQuoteSupport)
}

// A Certificates collection that is absent or lists no IDevID sends the client to HPE's OEM path.
// One the BMC failed to list must surface as that failure, not as a miss at a path an iDRAC never
// served.
func TestIDevIDChainFallsBackUnlessTheCollectionFailedToList(t *testing.T) {
	cert, err := json.Marshal(map[string]string{
		"CertificateString": "-----BEGIN CERTIFICATE-----\nMIIBAA==\n-----END CERTIFICATE-----\n",
	})
	require.NoError(t, err)

	t.Run("an iLO with no collection uses the OEM path", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/redfish/v1/Managers":
				_, _ = w.Write([]byte(`{"Members":[{"@odata.id":"/redfish/v1/Managers/1"}]}`))
			case "/redfish/v1/Managers/1" + hpeIDevIDSuffix:
				_, _ = w.Write(cert)
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		chain, err := clientFor(server).IDevIDChain(t.Context())

		require.NoError(t, err)
		assert.Len(t, chain, 1)
	})

	t.Run("an iLO that answers the collection with its schema stub uses the OEM path", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/redfish/v1/Managers":
				_, _ = w.Write([]byte(`{"Members":[{"@odata.id":"/redfish/v1/Managers/1"}]}`))
			case "/redfish/v1/Managers/1/Certificates":
				_, _ = w.Write([]byte("{\n  error:\n  {\n    code: string,\n    message: string\n  }\n}"))
			case "/redfish/v1/Managers/1" + hpeIDevIDSuffix:
				_, _ = w.Write(cert)
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		chain, err := clientFor(server).IDevIDChain(t.Context())

		require.NoError(t, err)
		assert.Len(t, chain, 1)
	})

	t.Run("an iDRAC that cannot list its collection says so", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/redfish/v1/Managers":
				_, _ = w.Write([]byte(`{"Members":[{"@odata.id":"/redfish/v1/Managers/iDRAC.Embedded.1"}]}`))
			case "/redfish/v1/Managers/iDRAC.Embedded.1/Certificates":
				http.Error(w, "internal error", http.StatusInternalServerError)
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		_, err := clientFor(server).IDevIDChain(t.Context())

		require.ErrorContains(t, err, "/redfish/v1/Managers/iDRAC.Embedded.1/Certificates returned 500")
		assert.NotContains(t, err.Error(), hpeIDevIDSuffix)
	})

	t.Run("a BMC with neither says so", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/redfish/v1/Managers":
				_, _ = w.Write([]byte(`{"Members":[{"@odata.id":"/redfish/v1/Managers/iDRAC.Embedded.1"}]}`))
			case "/redfish/v1/Managers/iDRAC.Embedded.1/Certificates":
				_, _ = w.Write([]byte(`{"Members":[]}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		_, err := clientFor(server).IDevIDChain(t.Context())

		require.ErrorIs(t, err, ErrNotFound)
		assert.ErrorContains(t, err, "lists no IDevID")
	})
}

// Every passthrough device and then the quote search the same ComponentIntegrity members, so the
// collection is read once per client rather than once per search.
func TestComponentIntegrityIsReadOncePerClient(t *testing.T) {
	var mu sync.Mutex
	reads := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reads[r.URL.Path]++
		mu.Unlock()
		if !serveTPMDiscovery(w, r) {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := clientFor(server)

	for range 2 {
		_, _, _, err := client.ComponentIntegrityFor(t.Context(), testMAC)
		require.ErrorContains(t, err, "no SPDM component on the BMC reports MAC")
	}
	target, err := client.quoteTarget(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "/quote", target)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, reads["/redfish/v1/ComponentIntegrity"])
	assert.Equal(t, 1, reads["/redfish/v1/ComponentIntegrity/TPM-1"])
}

// The client sends the nonce and PCR selection exactly as given. How long a nonce a BMC will sign
// intact is the caller's decision, not something the client fixes up.
func TestTPMSignedMeasurementsSendsTheRequestUnmodified(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveTPMDiscovery(w, r) {
			return
		}
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&got))
		_, _ = w.Write([]byte(`{"SignedMeasurements":"AAECAw=="}`))
	}))
	defer server.Close()

	nonce := strings.Repeat("ab", 32)
	blob, err := clientFor(server).TPMSignedMeasurements(t.Context(), nonce, "PCR0")

	require.NoError(t, err)
	assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03}, blob, "the blob is returned raw for the caller to parse")
	assert.Equal(t, nonce, got["Nonce"], "the nonce must not be truncated or re-encoded")
	assert.Equal(t, "PCR0", got["PCRSelection"], "a plain string, not an array")
}

func TestTPMSignedMeasurementsRejectsAnEmptyOrUndecodableBlob(t *testing.T) {
	// The discovery paths have to be served, or the call returns ErrNoQuoteSupport before it
	// ever looks at the blob and the test passes for the wrong reason.
	for _, tt := range []struct{ name, body, wantErr string }{
		{"empty", `{"SignedMeasurements":""}`, "empty"},
		{"not base64", `{"SignedMeasurements":"not base64!"}`, "base64"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !serveTPMDiscovery(w, r) {
					_, _ = w.Write([]byte(tt.body))
				}
			}))
			defer server.Close()

			_, err := clientFor(server).TPMSignedMeasurements(t.Context(), "abcdef", "PCR0")

			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

// Only the TPM covering the BMC's own manager is quoted. A host TPM listed first, with the same
// action, would put the host's PCR where the BMC's belongs.
func TestQuoteTargetIgnoresAHostTPM(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redfish/v1/ComponentIntegrity":
			_, _ = w.Write([]byte(`{"Members":[
				{"@odata.id":"/redfish/v1/ComponentIntegrity/TPM-0"},
				{"@odata.id":"/redfish/v1/ComponentIntegrity/TPM-1"}]}`))
		case "/redfish/v1/ComponentIntegrity/TPM-0":
			_, _ = w.Write([]byte(`{"ComponentIntegrityType":"TPM","TargetComponentURI":"/redfish/v1/Systems/1",
				"Actions":{"#ComponentIntegrity.TPMGetSignedMeasurements":{"target":"/host-quote"}}}`))
		default:
			if !serveTPMDiscovery(w, r) {
				http.NotFound(w, r)
			}
		}
	}))
	defer server.Close()

	target, err := clientFor(server).quoteTarget(t.Context())

	require.NoError(t, err)
	assert.Equal(t, "/quote", target)
}

// A TPM member the BMC failed to serve may be the one with the action, so it must not read as a BMC
// that cannot quote, and must be read again on the next attempt.
func TestQuoteTargetDoesNotMistakeAnUnreadableMemberForNoSupport(t *testing.T) {
	var mu sync.Mutex
	reads := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redfish/v1/ComponentIntegrity/TPM-1" {
			mu.Lock()
			reads++
			mu.Unlock()
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		if !serveTPMDiscovery(w, r) {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := clientFor(server)

	for range 2 {
		_, err := client.TPMSignedMeasurements(t.Context(), "abcdef", "PCR0")
		require.ErrorContains(t, err, "returned 503")
		assert.NotErrorIs(t, err, ErrNoQuoteSupport)
	}
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 2, reads, "a snapshot with an unreadable member must not be cached")
}

// The measurement set is decoded field by field from what the BMC serves.
func TestComponentIntegrityForDecodesTheMeasurementSet(t *testing.T) {
	spdm := `"ComponentIntegrityTypeVersion":"1.2.0",
		"SPDM":{"IdentityAuthentication":{"ResponderAuthentication":{"VerificationStatus":"Success"}},
		"MeasurementSet":{"MeasurementSpecification":"DMTF","Measurements":[
			{"MeasurementIndex":1,"Measurement":"YWJj","MeasurementType":"ImmutableROM",
			 "MeasurementHashAlgorithm":"TPM_ALG_SHA_256"}]}}`
	server := fakeBMCWithSPDM(t, "/redfish/v1/Chassis/1/NetworkAdapters/DA000000", spdm)
	defer server.Close()

	ci, _, _, err := clientFor(server).ComponentIntegrityFor(t.Context(), testMAC)

	require.NoError(t, err)
	assert.Equal(t, "1.2.0", ci.TypeVersion)
	assert.Equal(t, VerificationSuccess, ci.SPDM.IdentityAuthentication.ResponderAuthentication.VerificationStatus)
	assert.Equal(t, "DMTF", ci.SPDM.MeasurementSet.MeasurementSpecification)
	require.Len(t, ci.SPDM.MeasurementSet.Measurements, 1)
	m := ci.SPDM.MeasurementSet.Measurements[0]
	assert.Equal(t, 1, m.MeasurementIndex)
	assert.Equal(t, "YWJj", m.Measurement)
	assert.Equal(t, "ImmutableROM", m.MeasurementType)
	assert.Equal(t, "TPM_ALG_SHA_256", m.MeasurementHashAlgorithm)
}

// Some iLO versions list a device twice, once without measurements. The entry with measurements
// must win whichever order the BMC lists them in.
func TestComponentIntegrityForPrefersTheEntryWithMeasurements(t *testing.T) {
	for name, members := range map[string][]string{
		"measured listed second": {"Bare", "Measured"},
		"measured listed first":  {"Measured", "Bare"},
	} {
		t.Run(name, func(t *testing.T) {
			server, _ := serveRoutes(t, duplicateRoutes(members[0], members[1]))

			ci, _, _, err := clientFor(server).ComponentIntegrityFor(t.Context(), testMAC)

			require.NoError(t, err)
			assert.Equal(t, "Measured", ci.ID)
		})
	}
}

// The preference holds only between entries that can be read: one that cannot does not stop a bare
// duplicate from matching.
func TestComponentIntegrityForMatchesABareEntryWhenTheMeasuredOneIsUnreadable(t *testing.T) {
	routes := duplicateRoutes("Bare", "Measured")
	delete(routes, "/redfish/v1/ComponentIntegrity/Measured")
	server, _ := serveRoutes(t, routes)

	ci, _, _, err := clientFor(server).ComponentIntegrityFor(t.Context(), testMAC)

	require.NoError(t, err)
	assert.Equal(t, "Bare", ci.ID)
}

// duplicateRoutes is bmcRoutes with the NIC listed twice, as Bare (no measurements) and Measured,
// in the given order.
func duplicateRoutes(first, second string) map[string]string {
	const adapterURI = "/redfish/v1/Chassis/1/NetworkAdapters/DA000000"
	routes := bmcRoutes(adapterURI, "")
	routes["/redfish/v1/ComponentIntegrity"] = `{"Members":[
		{"@odata.id":"/redfish/v1/ComponentIntegrity/` + first + `"},
		{"@odata.id":"/redfish/v1/ComponentIntegrity/` + second + `"}]}`
	routes["/redfish/v1/ComponentIntegrity/Bare"] = `{"Id":"Bare","ComponentIntegrityType":"SPDM",
		"SPDM":{},"TargetComponentURI":"` + adapterURI + `"}`
	routes["/redfish/v1/ComponentIntegrity/Measured"] = `{"Id":"Measured","ComponentIntegrityType":"SPDM",
		"SPDM":{"MeasurementSet":{"Measurements":[{"MeasurementIndex":1,"Measurement":"YWJj"}]}},
		"TargetComponentURI":"` + adapterURI + `"}`
	return routes
}

// Every passthrough NIC searches the same components, so a later lookup reuses the adapters earlier
// ones resolved, and the ports of each adapter they read in full, rather than walking the BMC again.
func TestComponentIntegrityForResolvesEachAdapterOncePerClient(t *testing.T) {
	server, reads := serveRoutes(t, bmcRoutes("/redfish/v1/Chassis/1/NetworkAdapters/00000000", ""))
	client := clientFor(server)

	// A MAC the adapter does not carry reads all of it; the next lookup finds testMAC in what was read.
	_, _, _, err := client.ComponentIntegrityFor(t.Context(), "aa:bb:cc:dd:ee:ff")
	require.ErrorContains(t, err, "no SPDM component on the BMC reports MAC")
	_, _, bmcMAC, err := client.ComponentIntegrityFor(t.Context(), testMAC)
	require.NoError(t, err)
	assert.Equal(t, testMAC, bmcMAC)

	for _, path := range []string{
		"/redfish/v1/Chassis/1/NetworkAdapters/00000000",
		"/redfish/v1/Chassis/1/NetworkAdapters",
		"/redfish/v1/Chassis/1/NetworkAdapters/DA000000",
		"/redfish/v1/Chassis/1/NetworkAdapters/DA000000/Ports",
		"/redfish/v1/Chassis/1/NetworkAdapters/DA000000/Ports/1",
	} {
		assert.Equal(t, 1, reads(path), path)
	}
}

// A lookup that stops at its match has read only part of the adapter, so nothing is remembered: the
// other port's NIC must still be found on the same client.
func TestComponentIntegrityForFindsBothPortsOfADualPortAdapter(t *testing.T) {
	const otherMAC = "00:00:5e:00:53:11"
	routes := bmcRoutes("/redfish/v1/Chassis/1/NetworkAdapters/DA000000", "")
	routes["/redfish/v1/Chassis/1/NetworkAdapters/DA000000/Ports"] = `{"Members":[
		{"@odata.id":"/redfish/v1/Chassis/1/NetworkAdapters/DA000000/Ports/1"},
		{"@odata.id":"/redfish/v1/Chassis/1/NetworkAdapters/DA000000/Ports/2"}]}`
	routes["/redfish/v1/Chassis/1/NetworkAdapters/DA000000/Ports/2"] = `{
		"Ethernet":{"AssociatedMACAddresses":["` + otherMAC + `"]}}`
	server, _ := serveRoutes(t, routes)
	client := clientFor(server)

	for _, mac := range []string{testMAC, otherMAC} {
		_, _, bmcMAC, err := client.ComponentIntegrityFor(t.Context(), mac)
		require.NoError(t, err, mac)
		assert.Equal(t, mac, bmcMAC)
	}
}

// A port that could not be read leaves the adapter's MACs unknown rather than empty, so the next
// lookup reads them again.
func TestComponentIntegrityForRereadsAnAdapterWithAnUnreadablePort(t *testing.T) {
	const port = "/redfish/v1/Chassis/1/NetworkAdapters/DA000000/Ports/1"
	routes := bmcRoutes("/redfish/v1/Chassis/1/NetworkAdapters/DA000000", "")
	var portDown atomic.Bool
	portDown.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := routes[r.URL.Path]
		if !ok || (r.URL.Path == port && portDown.Load()) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	client := clientFor(server)

	_, _, _, err := client.ComponentIntegrityFor(t.Context(), testMAC)
	require.ErrorContains(t, err, "some were unreadable")

	portDown.Store(false)
	_, _, bmcMAC, err := client.ComponentIntegrityFor(t.Context(), testMAC)
	require.NoError(t, err)
	assert.Equal(t, testMAC, bmcMAC)
}

// A target that could not be read is not remembered as "not an adapter", so the next lookup reads it
// again instead of reporting a definite miss.
func TestComponentIntegrityForRereadsATargetThatCouldNotBeRead(t *testing.T) {
	const target = "/redfish/v1/Chassis/1/NetworkAdapters/DA000000"
	routes := bmcRoutes(target, "")
	var targetDown atomic.Bool
	targetDown.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := routes[r.URL.Path]
		if !ok || (r.URL.Path == target && targetDown.Load()) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	client := clientFor(server)

	_, _, _, err := client.ComponentIntegrityFor(t.Context(), testMAC)
	require.ErrorContains(t, err, "some were unreadable")

	targetDown.Store(false)
	_, _, bmcMAC, err := client.ComponentIntegrityFor(t.Context(), testMAC)
	require.NoError(t, err)
	assert.Equal(t, testMAC, bmcMAC)
}
