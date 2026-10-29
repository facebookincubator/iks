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

// Package redfish is a small client for the parts of a BMC's Redfish service that describe
// device integrity: the ComponentIntegrity collection (SPDM measurement sets and the TPM
// signed-measurement action), the manager's IEEE 802.1AR identity certificate, and the network
// adapters and ports used to tie a ComponentIntegrity entry to a host NIC.
//
// The caller supplies the *http.Client, and with it the transport and its TLS policy. Requests
// carry the credentials in a Basic Auth header.
package redfish

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const (
	// Collections, not resources: the member names are vendor-chosen. HPE serves Managers/1 and
	// Systems/1, Dell serves Managers/iDRAC.Embedded.1 and Systems/System.Embedded.1.
	managersPath           = "/redfish/v1/Managers"
	systemsPath            = "/redfish/v1/Systems"
	componentIntegrityPath = "/redfish/v1/ComponentIntegrity"

	// hpeIDevIDSuffix is where, under its manager, HPE keeps the IEEE 802.1AR factory identity.
	// Dell publishes its IDevID in the standard per-manager Certificates collection instead, so
	// that is tried first and this is the fallback.
	hpeIDevIDSuffix = "/SecurityService/iLOIDevID/Certificates/1"
)

// VerificationSuccess is the VerificationStatus a BMC reports when it says it authenticated a
// device over SPDM, which is the BMC's unsigned claim. The other value is Failed; a member with no
// status has not been verified. Only Success comes with measurements.
const VerificationSuccess = "Success"

// Client talks to one BMC. It is not safe for concurrent use: it caches what it has resolved.
type Client struct {
	baseURL  string
	user     string
	password string
	http     *http.Client

	// manager is the BMC's own resource path, resolved once per client.
	manager string
	// integrity is the ComponentIntegrity collection, listed once per client: every device lookup
	// and the signed-measurement action search the same members, and each read is a round trip.
	// Members that failed to read are retried on the next lookup.
	integrity *integritySnapshot
	// targets and portMACs keep what a device lookup resolved, so the next lookup does not walk
	// the BMC again: each component's adapter (nil when it is definitively not one), and the port
	// MACs of each adapter that was read in full without a match.
	targets  map[string]*NetworkAdapter
	portMACs map[string][]string
}

// NewClient returns a Client for the Redfish service at endpoint, e.g. "https://bmc.example.com".
// httpClient carries the transport, its TLS policy and its timeout. Every request closes its
// connection, whatever the transport's keep-alive setting: see do.
func NewClient(endpoint, user, password string, httpClient *http.Client) *Client {
	return &Client{
		baseURL:  strings.TrimRight(endpoint, "/"),
		user:     user,
		password: password,
		http:     httpClient,
	}
}

// ErrNotFound marks a 404, so a caller can tell a resource that does not exist from one it could
// not read.
var ErrNotFound = errors.New("not found")

// errUndecodable marks a response that arrived but did not decode, which some BMCs serve with a
// 200 for a resource that does not exist.
var errUndecodable = errors.New("failed to decode response")

// maxResponseSize bounds a response body; Redfish resources are a few kilobytes.
const maxResponseSize = 1 << 20

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to encode request for %s: %w", path, err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("failed to build request for %s: %w", path, err)
	}
	req.SetBasicAuth(c.user, c.password)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// Some BMCs answer a POST on a reused connection with "EOF", and Go will not retry a POST. A
	// POST can be handed any idle connection an earlier GET left behind, so none is ever reused.
	req.Close = true

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request to %s failed: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// A BMC error page can be large and ends up in an attestation error.
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		err = fmt.Errorf("%s %s returned %s: %s", method, path, resp.Status, strings.TrimSpace(string(detail)))
		if resp.StatusCode == http.StatusNotFound {
			err = fmt.Errorf("%w: %w", ErrNotFound, err)
		}
		return err
	}
	if out == nil {
		return nil
	}
	// Read first, so a connection that fails mid-body is not mistaken for a body that is not JSON.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return fmt.Errorf("failed to read response from %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%w from %s: %w", errUndecodable, path, err)
	}
	return nil
}

// idevidPath locates the BMC's 802.1AR factory identity, and reports whether it fell back to HPE's
// path. Dell publishes it in the standard per-manager Certificates collection, named for the key
// type (iDEVID_ECC_NIST_P384); HPE keeps it under an OEM SecurityService path outside that
// collection. A collection that is absent or lists no IDevID falls back to the OEM path under the
// same manager, as does one answered with the schema stub iLO serves for a resource it lacks. One
// the BMC failed to list fails instead, rather than surfacing as a miss at a path that BMC may never
// serve.
func (c *Client) idevidPath(ctx context.Context) (string, bool, error) {
	manager, err := c.managerPath(ctx)
	if err != nil {
		return "", false, err
	}
	var certs collection
	err = c.do(ctx, http.MethodGet, manager+"/Certificates", nil, &certs)
	if err != nil && !errors.Is(err, ErrNotFound) && !errors.Is(err, errUndecodable) {
		return "", false, err
	}
	for _, m := range certs.Members {
		if strings.Contains(strings.ToUpper(m.ID), "IDEVID") {
			return m.ID, false, nil
		}
	}
	return manager + hpeIDevIDSuffix, true, nil
}

// IDevIDChain returns the BMC's factory identity chain in DER form, leaf first, exactly as the BMC
// serves it.
func (c *Client) IDevIDChain(ctx context.Context) ([][]byte, error) {
	path, fallback, err := c.idevidPath(ctx)
	if err != nil {
		return nil, err
	}
	var cert struct {
		CertificateString string `json:"CertificateString"`
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &cert); err != nil {
		if fallback && errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("BMC lists no IDevID among its manager certificates or at HPE's OEM path: %w", err)
		}
		return nil, err
	}
	var chain [][]byte
	rest := []byte(cert.CertificateString)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			chain = append(chain, block.Bytes)
		}
	}
	if len(chain) == 0 {
		return nil, errors.New("BMC identity certificate is not PEM")
	}
	return chain, nil
}

// firstMember returns the single member of a Redfish collection. Both collections this is used
// on hold exactly one entry on a single-node server; more than one is an error rather than a guess.
func (c *Client) firstMember(ctx context.Context, collectionPath string) (string, error) {
	var members collection
	if err := c.do(ctx, http.MethodGet, collectionPath, nil, &members); err != nil {
		return "", err
	}
	if len(members.Members) != 1 {
		return "", fmt.Errorf("%s has %d members, expected exactly one", collectionPath, len(members.Members))
	}
	return members.Members[0].ID, nil
}

// managerPath resolves and caches the BMC's own Redfish resource, without a trailing slash.
func (c *Client) managerPath(ctx context.Context) (string, error) {
	if c.manager == "" {
		path, err := c.firstMember(ctx, managersPath)
		if err != nil {
			return "", err
		}
		c.manager = strings.TrimRight(path, "/")
	}
	return c.manager, nil
}

// Manager returns the BMC's own model and firmware version.
func (c *Client) Manager(ctx context.Context) (*Manager, error) {
	path, err := c.managerPath(ctx)
	if err != nil {
		return nil, err
	}
	var out Manager
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// System returns the platform inventory.
func (c *Client) System(ctx context.Context) (*System, error) {
	path, err := c.firstMember(ctx, systemsPath)
	if err != nil {
		return nil, err
	}
	var out System
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// integritySnapshot is the ComponentIntegrity collection as one client has read it so far.
type integritySnapshot struct {
	members []ComponentIntegrity
	// failed are the members that could not be read, retried on the next lookup.
	failed []string
	// unreadable joins the errors behind failed.
	unreadable error
}

// componentIntegrities lists the ComponentIntegrity collection once per client and reads each
// member until it succeeds: everything on the first lookup, then only what failed. A collection
// that fails to list is not cached, so the next caller tries again.
func (c *Client) componentIntegrities(ctx context.Context) (*integritySnapshot, error) {
	if c.integrity == nil {
		var list collection
		if err := c.do(ctx, http.MethodGet, componentIntegrityPath, nil, &list); err != nil {
			return nil, err
		}
		c.integrity = &integritySnapshot{}
		for _, member := range list.Members {
			c.integrity.failed = append(c.integrity.failed, member.ID)
		}
	}
	snapshot := c.integrity
	pending := snapshot.failed
	snapshot.failed, snapshot.unreadable = nil, nil
	for _, id := range pending {
		var ci ComponentIntegrity
		if err := c.do(ctx, http.MethodGet, id, nil, &ci); err != nil {
			snapshot.failed = append(snapshot.failed, id)
			snapshot.unreadable = errors.Join(snapshot.unreadable, err)
			continue
		}
		snapshot.members = append(snapshot.members, ci)
	}
	return snapshot, nil
}

// ComponentIntegrityFor finds the SPDM ComponentIntegrity entry whose target adapter reports the
// given MAC, the only identifier the BMC's view shares with the host's PCI view. It also returns
// the adapter and the MAC as the BMC spelled it. Of two readable entries for one device, the one
// that carries measurements is preferred.
func (c *Client) ComponentIntegrityFor(
	ctx context.Context, mac string,
) (*ComponentIntegrity, *NetworkAdapter, string, error) {
	snapshot, err := c.componentIntegrities(ctx)
	if err != nil {
		return nil, nil, "", err
	}

	// Some iLO versions list a device twice (seen on iLO 6 v1.71), so the entries that carry
	// measurements are tried first: of two readable entries, the measured one wins whatever order
	// the BMC lists them in. A measured entry that cannot be read does not stop a bare one matching.
	var measured, unmeasured []ComponentIntegrity
	for _, ci := range snapshot.members {
		if len(ci.SPDM.MeasurementSet.Measurements) > 0 {
			measured = append(measured, ci)
		} else {
			unmeasured = append(unmeasured, ci)
		}
	}

	// Read failures are surfaced only if the search comes up empty.
	unreadable := snapshot.unreadable
	for _, ci := range append(measured, unmeasured...) {
		// The TPM shares this collection.
		if ci.Type != "SPDM" || ci.TargetComponentURI == "" {
			continue
		}

		adapter, err := c.targetAdapter(ctx, &ci)
		if err != nil {
			unreadable = errors.Join(unreadable, err)
			continue
		}
		if adapter == nil {
			continue
		}
		bmcMAC, err := c.adapterMAC(ctx, adapter, mac)
		if err != nil {
			unreadable = errors.Join(unreadable, err)
			continue
		}
		if bmcMAC != "" {
			// Copies, so a caller cannot change what later lookups on this client see.
			ci.SPDM.MeasurementSet.Measurements = slices.Clone(ci.SPDM.MeasurementSet.Measurements)
			found := *adapter
			found.Controllers = slices.Clone(adapter.Controllers)
			return &ci, &found, bmcMAC, nil
		}
	}
	if unreadable != nil {
		return nil, nil, "", fmt.Errorf("no SPDM component on the BMC reports MAC %s; some were unreadable: %w",
			mac, unreadable)
	}
	return nil, nil, "", fmt.Errorf("no SPDM component on the BMC reports MAC %s", mac)
}

// slotOrdinalPattern pulls the slot number out of an id such as "OCPSlot-022-00".
var slotOrdinalPattern = regexp.MustCompile(`Slot-0*(\d+)`)

// targetAdapter resolves the network adapter a ComponentIntegrity describes. Three outcomes the
// caller must tell apart, since a truncated search must not read as a definitive miss:
//   - an adapter
//   - (nil, nil) when the target is definitively not an adapter (storage devices, the TPM)
//   - (nil, err) when the BMC stopped answering, so whether it is an adapter is unknown
//
// TargetComponentURI cannot be trusted to resolve: iLO 6 points it at adapter ids that do not
// exist and answers with a schema stub rather than a 404, so fall back to the slot in the id.
func (c *Client) targetAdapter(ctx context.Context, ci *ComponentIntegrity) (*NetworkAdapter, error) {
	if adapter, ok := c.targets[ci.ID]; ok {
		return adapter, nil
	}
	adapter, err := c.resolveTarget(ctx, ci)
	if err != nil {
		// Not kept: an unreadable target is tried again on the next lookup.
		return nil, err
	}
	if ci.ID != "" {
		if c.targets == nil {
			c.targets = make(map[string]*NetworkAdapter)
		}
		c.targets[ci.ID] = adapter
	}
	return adapter, nil
}

// resolveTarget is targetAdapter without the cache.
func (c *Client) resolveTarget(ctx context.Context, ci *ComponentIntegrity) (*NetworkAdapter, error) {
	var adapter NetworkAdapter
	directErr := c.do(ctx, http.MethodGet, ci.TargetComponentURI, nil, &adapter)
	if directErr == nil && adapter.Ports.ID != "" {
		adapter.SelfURI = ci.TargetComponentURI
		return &adapter, nil
	}

	match := slotOrdinalPattern.FindStringSubmatch(ci.ID)
	if match == nil {
		// No slot to fall back to; a non-nil directErr means unreadable rather than absent.
		return nil, directErr
	}
	slot, err := strconv.Atoi(match[1])
	if err != nil {
		return nil, fmt.Errorf("component %s names an unusable slot ordinal: %w", ci.ID, err)
	}

	// The collection URI is still right even when the adapter id in it is not.
	collectionURI := path.Dir(ci.TargetComponentURI)
	var adapters collection
	if err := c.do(ctx, http.MethodGet, collectionURI, nil, &adapters); err != nil {
		return nil, fmt.Errorf("adapter collection %s: %w", collectionURI, err)
	}

	var unreadable error
	for _, ref := range adapters.Members {
		var candidate NetworkAdapter
		if err := c.do(ctx, http.MethodGet, ref.ID, nil, &candidate); err != nil {
			unreadable = errors.Join(unreadable, err)
			continue
		}
		if candidate.Ports.ID == "" {
			continue
		}
		location := candidate.Location.PartLocation
		if location.LocationType == "Slot" && location.LocationOrdinalValue == slot {
			candidate.SelfURI = ref.ID
			return &candidate, nil
		}
	}
	// Nothing sits in that slot. Only a definitive answer if every candidate was readable, and the
	// target itself was missing or a stub rather than unreadable.
	if directErr != nil && !errors.Is(directErr, ErrNotFound) && !errors.Is(directErr, errUndecodable) {
		unreadable = errors.Join(unreadable, directErr)
	}
	return nil, unreadable
}

// adapterMAC returns the BMC's own spelling of mac if one of the adapter's ports carries it. An
// adapter whose every port was read without a match is remembered, so later lookups match against
// its MACs without reading its ports again.
func (c *Client) adapterMAC(ctx context.Context, adapter *NetworkAdapter, mac string) (string, error) {
	if adapter.Ports.ID == "" {
		return "", nil
	}
	if macs, ok := c.portMACs[adapter.Ports.ID]; ok {
		return matchMAC(macs, mac), nil
	}
	var ports collection
	if err := c.do(ctx, http.MethodGet, adapter.Ports.ID, nil, &ports); err != nil {
		return "", err
	}
	var macs []string
	var unreadable error
	for _, ref := range ports.Members {
		var port NetworkPort
		if err := c.do(ctx, http.MethodGet, ref.ID, nil, &port); err != nil {
			unreadable = errors.Join(unreadable, err)
			continue
		}
		for _, candidate := range port.Ethernet.AssociatedMACAddresses {
			macs = append(macs, strings.TrimSpace(candidate))
		}
		if found := matchMAC(macs, mac); found != "" {
			return found, nil
		}
	}
	if unreadable == nil {
		if c.portMACs == nil {
			c.portMACs = make(map[string][]string)
		}
		c.portMACs[adapter.Ports.ID] = macs
	}
	// "no match" and "could not tell" must not look the same to the caller.
	return "", unreadable
}

// matchMAC returns the entry of macs that is mac, in the BMC's own spelling, or "".
func matchMAC(macs []string, mac string) string {
	for _, candidate := range macs {
		if strings.EqualFold(candidate, mac) {
			return candidate
		}
	}
	return ""
}

// ErrNoQuoteSupport means the BMC exposes no TPMGetSignedMeasurements action for its own TPM, i.e.
// on no TPM member targeting its manager. Some BMCs list only a host TPM, or a TPM member that
// offers no such action.
var ErrNoQuoteSupport = errors.New("BMC exposes no TPM signed-measurement action for its own TPM")

// quoteTarget finds the ComponentIntegrity member covering the BMC's own TPM, i.e. targeting its
// manager, and returns the action URI it advertises rather than assembling one: the member name
// is vendor-chosen (HPE TPM-1) and so is the action. A TPM member targeting anything else, such as
// the host's TPM, is never quoted.
func (c *Client) quoteTarget(ctx context.Context) (string, error) {
	manager, err := c.managerPath(ctx)
	if err != nil {
		return "", err
	}
	snapshot, err := c.componentIntegrities(ctx)
	if err != nil {
		return "", err
	}
	for _, ci := range snapshot.members {
		if ci.Type != "TPM" || strings.TrimRight(ci.TargetComponentURI, "/") != manager {
			continue
		}
		if t := ci.Actions.TPMGetSignedMeasurements.Target; t != "" {
			return t, nil
		}
	}
	// The member that would have had the action may be the one that could not be read.
	if snapshot.unreadable != nil {
		return "", fmt.Errorf("no TPM signed-measurement action among the readable ComponentIntegrity members: %w",
			snapshot.unreadable)
	}
	return "", ErrNoQuoteSupport
}

// TPMSignedMeasurements invokes the TPMGetSignedMeasurements action the BMC advertises for its
// own TPM, with nonce and pcrSelection sent exactly as given, and returns the decoded
// SignedMeasurements blob. The blob's format is the BMC's; this client does not parse it.
func (c *Client) TPMSignedMeasurements(ctx context.Context, nonce, pcrSelection string) ([]byte, error) {
	var out struct {
		SignedMeasurements string `json:"SignedMeasurements"`
	}
	target, err := c.quoteTarget(ctx)
	if err != nil {
		return nil, err
	}
	// PCRSelection is a plain string even where AllowableValues lists several registers; at
	// least one BMC rejects an array with ActionParameterValueTypeError.
	req := map[string]any{"Nonce": nonce, "PCRSelection": pcrSelection}
	if err := c.do(ctx, http.MethodPost, target, req, &out); err != nil {
		return nil, err
	}
	if out.SignedMeasurements == "" {
		return nil, errors.New("BMC returned empty signed measurements")
	}
	blob, err := base64.StdEncoding.DecodeString(out.SignedMeasurements)
	if err != nil {
		return nil, fmt.Errorf("BMC signed measurements are not base64: %w", err)
	}
	return blob, nil
}
