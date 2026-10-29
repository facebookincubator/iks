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

// Package iommu reports which of a host's NICs sit in an IOMMU identity (passthrough) domain,
// where DMA translation is bypassed. It sees the netdevs in the caller's network namespace, so a
// PCI network function with no netdev there (bound to DPDK or vfio, or moved into another
// namespace) is not reported at all.
package iommu

import (
	"cmp"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// sysfsRoot is a variable so tests can point the enumeration at a fixture tree.
var sysfsRoot = "/sys"

// Option configures FindPassthroughNICs.
type Option func(*options)

type options struct {
	forced string
}

// WithForcedInterface also reports the named interface's PCI function even though its IOMMU group
// is not in passthrough, under the named interface when that is a port with a usable MAC and
// otherwise like any other function. It widens what is collected, never what is trusted: the NIC
// is marked Forced, and being reported this way says nothing about its DMA exposure, which is
// still reported as undetermined if it cannot be established.
func WithForcedInterface(name string) Option {
	return func(o *options) { o.forced = strings.TrimSpace(name) }
}

var (
	// A PCI function, e.g. 0000:43:00.0. The domain is %04x-printed, a minimum width: Intel VMD
	// allocates domains from 0x10000, so it can be wider.
	bdfPattern   = regexp.MustCompile(`^[0-9a-fA-F]{4,}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$`)
	groupPattern = regexp.MustCompile(`^[0-9]+$`)
	// The phys_port_name of a switchdev representor names the PF, VF or SF it stands in for,
	// e.g. pf0vf1, c1pf0sf2, or nfp's pf0s1 for a split PF. A port's is p<N>, with an optional line
	// card prefix (l<N>) or split suffix (s<N>), or absent on drivers without devlink ports.
	representorPattern = regexp.MustCompile(`^(c[0-9]+)?pf[0-9]+((vf|sf|s)[0-9]+)?$`)
)

var (
	// errNotPCI marks a netdev with no PCI function behind it: lo, bonds, veth, virtio, USB.
	errNotPCI = errors.New("not backed by a PCI function")
	// errOnlyRepresentors marks an exposed or forced function whose uplink is not in this namespace,
	// leaving only representors, whose MACs are their own rather than the port's.
	errOnlyRepresentors = errors.New(
		"only switchdev representors are visible on this function, and their MACs are not the port's")
)

// iommuDomainProtects maps known iommu_group/type values to whether DMA is translated. Listed
// positively so a domain the kernel adds later reads as unknown rather than as protected.
var iommuDomainProtects = map[string]bool{
	"dma":      true,
	"dma-fq":   true,
	"blocked":  true,
	"identity": false,
}

// PassthroughNIC is a NIC whose IOMMU group sits in an identity domain, i.e. DMA translation is
// bypassed for it. MAC is the address a management controller also reports for the port, so the
// two views can be joined on it (see readMAC). Forced marks a NIC named with WithForcedInterface
// rather than found in passthrough; its IOMMUGroup is empty when the group could not be read, in
// which case its BDF is also in Undetermined.
type PassthroughNIC struct {
	Interface  string
	BDF        string
	IOMMUGroup string
	MAC        string
	Forced     bool
}

// UndeterminedNIC is a NIC whose DMA exposure could not be established, or that has no usable MAC
// to join on; Reason says which. BDF is empty when the PCI function itself could not be resolved.
// A forced NIC can appear here and in NICs. An unreadable IOMMU state is not evidence of safety,
// so it is reported rather than dropped.
type UndeterminedNIC struct {
	Interface string
	BDF       string
	Reason    string
}

// Enumeration is what the host could establish about its NICs' DMA exposure.
type Enumeration struct {
	NICs         []PassthroughNIC
	Undetermined []UndeterminedNIC
}

// FindPassthroughNICs reports the DMA exposure of this host's NICs. It groups the netdevs in
// /sys/class/net by the PCI function behind them, skipping non-PCI netdevs (lo, bonds, veth,
// virtio, USB), and gives each function one verdict:
//   - /sys/kernel/iommu_groups/<group>/type: "identity" means DMA translation is bypassed, the DMA
//     domains mean it is not, anything else is undetermined
//   - the MAC address (see readMAC), the key the host's view is joined on, taken from the first of
//     the function's netdevs that has a usable one, never from a switchdev representor
//
// A netdev whose device link exists but cannot be read is undetermined. An empty NICs list is not
// an error: most hosts run with the IOMMU fully enabled. It is only trustworthy when Undetermined
// is also empty.
func FindPassthroughNICs(opts ...Option) (Enumeration, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}

	netDir := filepath.Join(sysfsRoot, "class", "net")
	entries, err := os.ReadDir(netDir)
	if err != nil {
		return Enumeration{}, fmt.Errorf("failed to list network interfaces: %w", err)
	}

	e := enumerator{netDir: netDir, forced: o.forced, reported: make(map[string]bool, len(entries))}
	var functions []*pciFunction
	byBDF := make(map[string]*pciFunction, len(entries))
	for _, entry := range entries {
		// Netdevs are links; a regular file here, such as bonding_masters, is a class attribute.
		if entry.Type().IsRegular() {
			continue
		}
		iface := entry.Name()
		bdf, err := resolveBDF(netDir, iface)
		if errors.Is(err, errNotPCI) {
			continue
		}
		if err != nil {
			e.undetermined(iface, "", err)
			continue
		}
		fn := byBDF[bdf]
		if fn == nil {
			fn = &pciFunction{bdf: bdf}
			byBDF[bdf] = fn
			functions = append(functions, fn)
		}
		if isRepresentor(netDir, iface) {
			fn.representors = append(fn.representors, iface)
		} else {
			fn.ports = append(fn.ports, iface)
		}
	}
	for _, fn := range functions {
		e.report(fn)
	}
	return e.out, nil
}

// pciFunction is a PCI network function and its netdevs in name order. A switchdev representor
// shares its PF's function but carries a random MAC of its own, so it is kept apart from the
// netdevs that are ports.
type pciFunction struct {
	bdf          string
	ports        []string
	representors []string
}

type enumerator struct {
	netDir   string
	forced   string
	out      Enumeration
	reported map[string]bool
}

// undetermined records a NIC that could not be used: once per PCI function, however many netdevs
// or reasons it has, or per interface when the function itself could not be resolved.
func (e *enumerator) undetermined(iface, bdf string, err error) {
	key := cmp.Or(bdf, iface)
	if e.reported[key] {
		return
	}
	e.reported[key] = true
	e.out.Undetermined = append(e.out.Undetermined, UndeterminedNIC{Interface: iface, BDF: bdf, Reason: err.Error()})
}

// report gives a function its verdict. DMA exposure is a property of the function, and every
// netdev on it shares the same device, so any of them can be classified.
func (e *enumerator) report(fn *pciFunction) {
	netdevs := slices.Concat(fn.ports, fn.representors)
	group, exposed, err := classify(e.netDir, netdevs[0])
	if err != nil {
		e.undetermined(netdevs[0], fn.bdf, err)
	}
	isForced := e.forced != "" && slices.Contains(netdevs, e.forced)
	if !isForced && (err != nil || !exposed) {
		return
	}

	// A forced port is tried first, so the NIC is collected under the name it was given when that
	// port has a usable MAC. A forced representor forces only its function.
	candidates := fn.ports
	if i := slices.Index(fn.ports, e.forced); i > 0 {
		candidates = slices.Concat([]string{e.forced}, fn.ports[:i], fn.ports[i+1:])
	}
	if len(candidates) == 0 {
		e.undetermined(netdevs[0], fn.bdf, errOnlyRepresentors)
		return
	}
	var firstErr error
	for _, iface := range candidates {
		mac, err := readMAC(e.netDir, iface)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		e.out.NICs = append(e.out.NICs, PassthroughNIC{
			Interface:  iface,
			BDF:        fn.bdf,
			IOMMUGroup: group,
			MAC:        mac,
			Forced:     !exposed,
		})
		return
	}
	e.undetermined(candidates[0], fn.bdf, firstErr)
}

// classify reports the IOMMU group and whether DMA translation is bypassed for it. An error
// means the state could not be established, which is distinct from "protected".
func classify(netDir, iface string) (string, bool, error) {
	group, err := readIOMMUGroup(netDir, iface)
	if err != nil {
		return "", false, err
	}
	raw, err := os.ReadFile(filepath.Join(sysfsRoot, "kernel", "iommu_groups", group, "type"))
	if err != nil {
		return group, false, fmt.Errorf("unreadable IOMMU domain for group %s: %w", group, err)
	}
	domain := strings.ToLower(strings.TrimSpace(string(raw)))
	protects, known := iommuDomainProtects[domain]
	if !known {
		return group, false, fmt.Errorf("unknown IOMMU domain %q for group %s", domain, group)
	}
	return group, !protects, nil
}

// resolveBDF returns errNotPCI for a netdev with no device link, which also covers one that went
// away after the directory was listed, and for a device that is not a PCI function. Any other
// failure leaves the netdev's DMA exposure unknown.
func resolveBDF(netDir, iface string) (string, error) {
	target, err := os.Readlink(filepath.Join(netDir, iface, "device"))
	if errors.Is(err, os.ErrNotExist) {
		return "", errNotPCI
	}
	if err != nil {
		return "", fmt.Errorf("unreadable device link: %w", err)
	}
	if bdf := filepath.Base(target); bdfPattern.MatchString(bdf) {
		return bdf, nil
	}
	return "", errNotPCI
}

func isRepresentor(netDir, iface string) bool {
	raw, err := os.ReadFile(filepath.Join(netDir, iface, "phys_port_name"))
	return err == nil && representorPattern.MatchString(strings.TrimSpace(string(raw)))
}

func readIOMMUGroup(netDir, iface string) (string, error) {
	target, err := os.Readlink(filepath.Join(netDir, iface, "device", "iommu_group"))
	if err != nil {
		return "", fmt.Errorf("no IOMMU group: %w", err)
	}
	group := filepath.Base(target)
	// Validated because it is interpolated into a path.
	if !groupPattern.MatchString(group) {
		return "", fmt.Errorf("malformed IOMMU group %q", group)
	}
	return group, nil
}

// readMAC returns the address a management controller reports for the port: perm_address when the
// driver exposes one, else bonding_slave/perm_hwaddr for an enslaved interface, else the current
// "address" of an interface that is not enslaved, which software can change. "address" is never
// used for an enslaved interface: the bonding driver overwrites it with the bond's MAC, and
// joining on that picks the wrong NIC. Any stat failure but ErrNotExist counts as enslaved.
func readMAC(netDir, iface string) (string, error) {
	enslaved := true
	var statErr error
	if _, err := os.Stat(filepath.Join(netDir, iface, "bonding_slave")); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			enslaved = false
		} else {
			statErr = err
		}
	}

	candidates := []string{"perm_address"}
	if enslaved {
		candidates = append(candidates, filepath.Join("bonding_slave", "perm_hwaddr"))
	} else {
		candidates = append(candidates, "address")
	}
	for _, name := range candidates {
		raw, err := os.ReadFile(filepath.Join(netDir, iface, name))
		if err != nil {
			continue
		}
		mac, err := net.ParseMAC(strings.TrimSpace(string(raw)))
		if err != nil {
			continue
		}
		// Port addresses are 6 bytes; devices with no permanent one read all zeroes.
		if len(mac) != 6 || mac[0]&0x01 != 0 || isZeroMAC(mac) {
			continue
		}
		return mac.String(), nil
	}
	if enslaved {
		if statErr != nil {
			return "", fmt.Errorf(
				"%s exposes no permanent MAC and its bonding state is unreadable, so the "+
					"address may belong to a bond; refusing to join on it: %w", iface, statErr)
		}
		return "", fmt.Errorf(
			"%s is enslaved to a bond and exposes no permanent MAC; refusing to join on the bond address", iface)
	}
	return "", fmt.Errorf("no usable MAC address for %s", iface)
}

func isZeroMAC(mac net.HardwareAddr) bool {
	for _, b := range mac {
		if b != 0 {
			return false
		}
	}
	return true
}
