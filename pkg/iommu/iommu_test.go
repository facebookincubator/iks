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

package iommu

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeIface builds the sysfs shape the enumeration walks:
//   - /bus/pci/devices/<bdf> with an iommu_group symlink to a group of the given domain type
//   - /class/net/<iface> with a device symlink to that PCI dir and an optional perm_address
func fakeIface(t *testing.T, root, iface, bdf, group, domain, mac string) {
	t.Helper()

	pciDir := filepath.Join(root, "bus", "pci", "devices", bdf)
	require.NoError(t, os.MkdirAll(pciDir, 0o755))

	if group != "" {
		groupDir := filepath.Join(root, "kernel", "iommu_groups", group)
		require.NoError(t, os.MkdirAll(groupDir, 0o755))
		if domain != "" {
			require.NoError(t, os.WriteFile(filepath.Join(groupDir, "type"), []byte(domain+"\n"), 0o600))
		}
		require.NoError(t, os.Symlink(groupDir, filepath.Join(pciDir, "iommu_group")))
	}

	netIface := filepath.Join(root, "class", "net", iface)
	require.NoError(t, os.MkdirAll(netIface, 0o755))
	require.NoError(t, os.Symlink(pciDir, filepath.Join(netIface, "device")))
	if mac != "" {
		require.NoError(t, os.WriteFile(filepath.Join(netIface, "perm_address"), []byte(mac+"\n"), 0o600))
	}
}

func withSysfs(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	old := sysfsRoot
	sysfsRoot = root
	t.Cleanup(func() { sysfsRoot = old })
	return root
}

// fakeSibling adds another netdev on 0000:43:00.0, the PCI function the tests that need one build,
// as a second port or a representor would be, and returns its /class/net directory.
func fakeSibling(t *testing.T, root, iface string) string {
	t.Helper()
	netIface := filepath.Join(root, "class", "net", iface)
	require.NoError(t, os.MkdirAll(netIface, 0o755))
	pciDir := filepath.Join(root, "bus", "pci", "devices", "0000:43:00.0")
	require.NoError(t, os.Symlink(pciDir, filepath.Join(netIface, "device")))
	return netIface
}

// setPortName gives a netdev the phys_port_name the kernel reports for its port flavour.
func setPortName(t *testing.T, netIface, name string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(netIface, "phys_port_name"), []byte(name+"\n"), 0o600))
}

func TestFindPassthroughNICsSelectsOnlyIdentityGroups(t *testing.T) {
	root := withSysfs(t)
	fakeIface(t, root, "eth0", "0000:43:00.0", "62", "identity", "00:00:5e:00:53:01")
	fakeIface(t, root, "eth1", "0000:44:00.0", "63", "DMA", "00:00:5e:00:53:02")

	devices, err := FindPassthroughNICs()
	require.NoError(t, err)
	require.Len(t, devices.NICs, 1)
	assert.Equal(t, "eth0", devices.NICs[0].Interface)
	assert.Equal(t, "0000:43:00.0", devices.NICs[0].BDF)
	assert.Equal(t, "62", devices.NICs[0].IOMMUGroup)
	assert.Equal(t, "00:00:5e:00:53:01", devices.NICs[0].MAC)
}

func TestFindPassthroughNICsEmptyWhenIOMMUEnforced(t *testing.T) {
	root := withSysfs(t)
	fakeIface(t, root, "eth0", "0000:43:00.0", "62", "DMA", "00:00:5e:00:53:01")

	devices, err := FindPassthroughNICs()
	require.NoError(t, err)
	assert.Empty(t, devices.NICs)
}

func TestFindPassthroughNICsSkipsVirtualInterfaces(t *testing.T) {
	root := withSysfs(t)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "class", "net", "lo"), 0o755))
	fakeIface(t, root, "eth0", "0000:43:00.0", "62", "identity", "00:00:5e:00:53:01")

	devices, err := FindPassthroughNICs()
	require.NoError(t, err)
	require.Len(t, devices.NICs, 1)
	assert.Equal(t, "eth0", devices.NICs[0].Interface)
}

func TestFindPassthroughNICsReportsAPassthroughNICWithNoMAC(t *testing.T) {
	root := withSysfs(t)
	// Without a MAC there is no key to join the host's view on.
	fakeIface(t, root, "eth0", "0000:43:00.0", "62", "identity", "")

	devices, err := FindPassthroughNICs()
	require.NoError(t, err)
	assert.Empty(t, devices.NICs)
	require.Len(t, devices.Undetermined, 1)
	assert.Equal(t, "eth0", devices.Undetermined[0].Interface)
	assert.Contains(t, devices.Undetermined[0].Reason, "no usable MAC")
}

func TestFindPassthroughNICsIgnoresAllZeroPermAddress(t *testing.T) {
	root := withSysfs(t)
	fakeIface(t, root, "eth0", "0000:43:00.0", "62", "identity", "")
	netIface := filepath.Join(root, "class", "net", "eth0")
	require.NoError(t, os.WriteFile(filepath.Join(netIface, "perm_address"), []byte("00:00:00:00:00:00\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(netIface, "address"), []byte("00:00:5e:00:53:01\n"), 0o600))

	devices, err := FindPassthroughNICs()
	require.NoError(t, err)
	require.Len(t, devices.NICs, 1)
	assert.Equal(t, "00:00:5e:00:53:01", devices.NICs[0].MAC)
}

// Some NICs leave perm_address empty, so the join key would otherwise be the shared bond MAC.
func TestFindPassthroughNICsPrefersSlavePermHwaddrOverBondMAC(t *testing.T) {
	root := withSysfs(t)
	fakeIface(t, root, "eth0", "0000:43:00.0", "62", "identity", "")
	netIface := filepath.Join(root, "class", "net", "eth0")
	require.NoError(t, os.WriteFile(filepath.Join(netIface, "perm_address"), []byte("\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(netIface, "address"), []byte("aa:bb:cc:dd:ee:ff\n"), 0o600))
	slaveDir := filepath.Join(netIface, "bonding_slave")
	require.NoError(t, os.MkdirAll(slaveDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(slaveDir, "perm_hwaddr"), []byte("00:00:5e:00:53:10\n"), 0o600))

	devices, err := FindPassthroughNICs()
	require.NoError(t, err)
	require.Len(t, devices.NICs, 1)
	assert.Equal(t, "00:00:5e:00:53:10", devices.NICs[0].MAC)
}

func TestFindPassthroughNICsRefusesBondMACWhenSlaveHasNoPermHwaddr(t *testing.T) {
	root := withSysfs(t)
	fakeIface(t, root, "eth0", "0000:43:00.0", "62", "identity", "")
	netIface := filepath.Join(root, "class", "net", "eth0")
	require.NoError(t, os.WriteFile(filepath.Join(netIface, "address"), []byte("aa:bb:cc:dd:ee:ff\n"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(netIface, "bonding_slave"), 0o755))

	devices, err := FindPassthroughNICs()
	require.NoError(t, err)
	assert.Empty(t, devices.NICs, "the bond MAC must never be used as the join key")
	require.Len(t, devices.Undetermined, 1)
	assert.Contains(t, devices.Undetermined[0].Reason, "enslaved to a bond")
}

// A bonding state that cannot be read may hide an enslaved NIC, whose address is the bond's.
func TestFindPassthroughNICsRefusesTheAddressWhenBondingStateIsUnreadable(t *testing.T) {
	root := withSysfs(t)
	fakeIface(t, root, "eth0", "0000:43:00.0", "62", "identity", "")
	netIface := filepath.Join(root, "class", "net", "eth0")
	require.NoError(t, os.WriteFile(filepath.Join(netIface, "address"), []byte("aa:bb:cc:dd:ee:ff\n"), 0o600))
	// A self-referencing link makes stat fail with ELOOP rather than ErrNotExist.
	require.NoError(t, os.Symlink("bonding_slave", filepath.Join(netIface, "bonding_slave")))

	devices, err := FindPassthroughNICs()
	require.NoError(t, err)
	assert.Empty(t, devices.NICs)
	require.Len(t, devices.Undetermined, 1)
	assert.Contains(t, devices.Undetermined[0].Reason, "bonding state is unreadable")
}

// No IOMMU group at all is the maximum-exposure state, not a clean one.
func TestFindPassthroughNICsReportsMissingIOMMUGroupAsUndetermined(t *testing.T) {
	root := withSysfs(t)
	fakeIface(t, root, "eth0", "0000:43:00.0", "", "", "00:00:5e:00:53:10")

	devices, err := FindPassthroughNICs()
	require.NoError(t, err)
	assert.Empty(t, devices.NICs)
	require.Len(t, devices.Undetermined, 1)
	assert.Contains(t, devices.Undetermined[0].Reason, "no IOMMU group")
}

// DMA exposure is a property of the PCI function, so a dual-port NIC yields one report, not two.
func TestFindPassthroughNICsReportsAnUnclassifiableFunctionOnce(t *testing.T) {
	root := withSysfs(t)
	fakeIface(t, root, "eth0", "0000:43:00.0", "", "", "00:00:5e:00:53:10")

	// eth1 is a second port on eth0's function.
	fakeSibling(t, root, "eth1")

	devices, err := FindPassthroughNICs()
	require.NoError(t, err)
	assert.Empty(t, devices.NICs)
	assert.Len(t, devices.Undetermined, 1, "one PCI function should yield one report")
}

// A group that is present but unparseable is a different state from no group at all.
func TestFindPassthroughNICsDistinguishesAMalformedGroupFromAMissingOne(t *testing.T) {
	root := withSysfs(t)
	fakeIface(t, root, "eth0", "0000:43:00.0", "not-a-number", "identity", "00:00:5e:00:53:10")

	devices, err := FindPassthroughNICs()
	require.NoError(t, err)
	require.Len(t, devices.Undetermined, 1)
	assert.Contains(t, devices.Undetermined[0].Reason, "malformed IOMMU group")
	assert.NotContains(t, devices.Undetermined[0].Reason, "no IOMMU group")
}

func TestFindPassthroughNICsReportsUnknownDomainAsUndetermined(t *testing.T) {
	root := withSysfs(t)
	fakeIface(t, root, "eth0", "0000:43:00.0", "62", "some-future-domain", "00:00:5e:00:53:10")

	devices, err := FindPassthroughNICs()
	require.NoError(t, err)
	assert.Empty(t, devices.NICs)
	require.Len(t, devices.Undetermined, 1)
	assert.Contains(t, devices.Undetermined[0].Reason, "unknown IOMMU domain")
}

func TestFindPassthroughNICsTreatsDMADomainsAsProtected(t *testing.T) {
	for _, domain := range []string{"DMA", "dma-fq", "blocked"} {
		t.Run(domain, func(t *testing.T) {
			root := withSysfs(t)
			fakeIface(t, root, "eth0", "0000:43:00.0", "62", domain, "00:00:5e:00:53:10")

			devices, err := FindPassthroughNICs()
			require.NoError(t, err)
			assert.Empty(t, devices.NICs)
			assert.Empty(t, devices.Undetermined, "a protecting domain is determined, not unknown")
		})
	}
}

func TestFindPassthroughNICsSkipsNonPCIParents(t *testing.T) {
	root := withSysfs(t)
	fakeIface(t, root, "eth0", "virtio0", "62", "identity", "00:00:5e:00:53:10")

	devices, err := FindPassthroughNICs()
	require.NoError(t, err)
	assert.Empty(t, devices.NICs)
	assert.Empty(t, devices.Undetermined, "a non-PCI parent has no IOMMU group by construction")
}

// A device link that exists but cannot be read proves nothing about the NIC behind it.
func TestFindPassthroughNICsReportsAnUnreadableDeviceLink(t *testing.T) {
	root := withSysfs(t)
	for _, iface := range []string{"eth0", "eth1"} {
		netIface := filepath.Join(root, "class", "net", iface)
		require.NoError(t, os.MkdirAll(netIface, 0o755))
		// A regular file makes readlink fail with EINVAL rather than ErrNotExist.
		require.NoError(t, os.WriteFile(filepath.Join(netIface, "device"), nil, 0o600))
	}

	devices, err := FindPassthroughNICs()
	require.NoError(t, err)
	assert.Empty(t, devices.NICs)
	require.Len(t, devices.Undetermined, 2, "with no PCI function to key on, each interface is its own report")
	assert.Equal(t, "eth0", devices.Undetermined[0].Interface)
	assert.Empty(t, devices.Undetermined[0].BDF)
	assert.Contains(t, devices.Undetermined[0].Reason, "unreadable device link")
}

// A VF representor shares its PF's function but not its MAC, so the uplink supplies the MAC even
// when the representor sorts first.
func TestFindPassthroughNICsTakesTheMACFromTheUplinkNotARepresentor(t *testing.T) {
	root := withSysfs(t)
	fakeIface(t, root, "eth1", "0000:43:00.0", "62", "identity", "00:00:5e:00:53:01")
	uplink := filepath.Join(root, "class", "net", "eth1")
	setPortName(t, uplink, "p0")

	rep := fakeSibling(t, root, "eth0")
	setPortName(t, rep, "pf0vf0")
	require.NoError(t, os.WriteFile(filepath.Join(rep, "address"), []byte("00:00:5e:00:53:99\n"), 0o600))

	devices, err := FindPassthroughNICs()
	require.NoError(t, err)
	require.Len(t, devices.NICs, 1)
	assert.Equal(t, "eth1", devices.NICs[0].Interface)
	assert.Equal(t, "00:00:5e:00:53:01", devices.NICs[0].MAC)
}

// With its uplink in another namespace, an exposed function shows only representors, and a
// representor's MAC is its own, so there is nothing to join on.
func TestFindPassthroughNICsReportsAFunctionWithOnlyRepresentorsAsUndetermined(t *testing.T) {
	root := withSysfs(t)
	fakeIface(t, root, "eth0", "0000:43:00.0", "62", "identity", "00:00:5e:00:53:99")
	rep := filepath.Join(root, "class", "net", "eth0")
	setPortName(t, rep, "pf0vf0")

	devices, err := FindPassthroughNICs()
	require.NoError(t, err)
	assert.Empty(t, devices.NICs)
	require.Len(t, devices.Undetermined, 1)
	assert.Contains(t, devices.Undetermined[0].Reason, "only switchdev representors")
}

// A function's MAC comes from whichever of its ports has a usable one, so a sibling port is not
// lost because the first in name order has none.
func TestFindPassthroughNICsTakesTheMACFromAnyPortOnTheFunction(t *testing.T) {
	root := withSysfs(t)
	fakeIface(t, root, "eth0", "0000:43:00.0", "62", "identity", "")
	eth1 := fakeSibling(t, root, "eth1")
	require.NoError(t, os.WriteFile(filepath.Join(eth1, "perm_address"), []byte("00:00:5e:00:53:02\n"), 0o600))

	devices, err := FindPassthroughNICs()
	require.NoError(t, err)
	require.Len(t, devices.NICs, 1)
	assert.Equal(t, "eth1", devices.NICs[0].Interface)
	assert.Equal(t, "00:00:5e:00:53:02", devices.NICs[0].MAC)
	assert.Empty(t, devices.Undetermined)
}

// bonding_masters sits in /sys/class/net as a regular file whenever the bonding module is loaded.
func TestFindPassthroughNICsIgnoresClassAttributes(t *testing.T) {
	root := withSysfs(t)
	fakeIface(t, root, "eth0", "0000:43:00.0", "62", "identity", "00:00:5e:00:53:01")
	require.NoError(t, os.WriteFile(filepath.Join(root, "class", "net", "bonding_masters"), []byte("bond0\n"), 0o600))

	devices, err := FindPassthroughNICs()
	require.NoError(t, err)
	require.Len(t, devices.NICs, 1)
	assert.Empty(t, devices.Undetermined)
}

// Representor names follow the kernel's devlink port flavours, plus nfp's split PF; a port's never
// match.
func TestIsRepresentorMatchesOnlyRepresentorPortNames(t *testing.T) {
	root := withSysfs(t)
	netDir := filepath.Join(root, "class", "net")
	for _, tt := range []struct {
		portName string
		want     bool
	}{
		{"pf0", true},
		{"c1pf0", true},
		{"pf0vf1", true},
		{"c1pf0vf1", true},
		{"pf0sf2", true},
		{"pf0s1", true},
		{"p0", false},
		{"p0s1", false},
		{"l1p1", false},
		{"l1p1s2", false},
		{"", false},
	} {
		t.Run(tt.portName, func(t *testing.T) {
			iface := "eth-" + tt.portName
			netIface := filepath.Join(netDir, iface)
			require.NoError(t, os.MkdirAll(netIface, 0o755))
			setPortName(t, netIface, tt.portName)
			assert.Equal(t, tt.want, isRepresentor(netDir, iface))
		})
	}
}

// Intel VMD allocates PCI domains from 0x10000, which prints wider than four hex digits.
func TestFindPassthroughNICsAcceptsWideDomainBDF(t *testing.T) {
	root := withSysfs(t)
	fakeIface(t, root, "eth0", "10000:43:00.0", "62", "identity", "00:00:5e:00:53:10")

	devices, err := FindPassthroughNICs()
	require.NoError(t, err)
	require.Len(t, devices.NICs, 1)
	assert.Equal(t, "10000:43:00.0", devices.NICs[0].BDF)
}

func TestFindPassthroughNICsRejectsMulticastAndNon48BitMACs(t *testing.T) {
	for name, mac := range map[string]string{
		"multicast": "01:00:5e:00:00:01",
		"broadcast": "ff:ff:ff:ff:ff:ff",
		"eui64":     "02:00:00:00:00:00:00:01",
	} {
		t.Run(name, func(t *testing.T) {
			root := withSysfs(t)
			fakeIface(t, root, "eth0", "0000:43:00.0", "62", "identity", mac)

			devices, err := FindPassthroughNICs()
			require.NoError(t, err)
			assert.Empty(t, devices.NICs, "%s cannot be a port address", name)
			require.Len(t, devices.Undetermined, 1)
		})
	}
}

func TestFindPassthroughNICsForceOverride(t *testing.T) {
	root := withSysfs(t)
	fakeIface(t, root, "eth0", "0000:43:00.0", "62", "DMA-FQ", "00:00:5e:00:53:01")

	devices, err := FindPassthroughNICs(WithForcedInterface("eth0"))
	require.NoError(t, err)
	require.Len(t, devices.NICs, 1)
	assert.Equal(t, "eth0", devices.NICs[0].Interface)
	assert.True(t, devices.NICs[0].Forced, "a device selected by the override must be marked forced")
}

func TestFindPassthroughNICsForceOnlyNamedInterface(t *testing.T) {
	root := withSysfs(t)
	fakeIface(t, root, "eth0", "0000:43:00.0", "62", "DMA-FQ", "00:00:5e:00:53:01")
	fakeIface(t, root, "eth1", "0000:44:00.0", "63", "DMA-FQ", "00:00:5e:00:53:02")

	devices, err := FindPassthroughNICs(WithForcedInterface("eth0"))
	require.NoError(t, err)
	require.Len(t, devices.NICs, 1, "the override names one interface, not all of them")
	assert.Equal(t, "eth0", devices.NICs[0].Interface)
}

func TestFindPassthroughNICsGenuinePassthroughIsNotForced(t *testing.T) {
	root := withSysfs(t)
	fakeIface(t, root, "eth0", "0000:43:00.0", "62", "identity", "00:00:5e:00:53:01")

	devices, err := FindPassthroughNICs(WithForcedInterface("eth0"))
	require.NoError(t, err)
	require.Len(t, devices.NICs, 1)
	assert.False(t, devices.NICs[0].Forced,
		"naming an interface that is genuinely in passthrough must not mark it forced")
}

// A forced interface is collected even when sysfs exposes no IOMMU group for it.
func TestFindPassthroughNICsForceWithoutIOMMUGroup(t *testing.T) {
	root := withSysfs(t)
	fakeIface(t, root, "eth0", "0000:43:00.0", "", "", "00:00:5e:00:53:10")

	devices, err := FindPassthroughNICs(WithForcedInterface("eth0"))
	require.NoError(t, err)
	require.Len(t, devices.NICs, 1)
	assert.Equal(t, "eth0", devices.NICs[0].Interface)
	assert.True(t, devices.NICs[0].Forced)
	// Forcing collects the NIC; it must not hide that its exposure is unknown.
	require.Len(t, devices.Undetermined, 1)
	assert.Contains(t, devices.Undetermined[0].Reason, "no IOMMU group")
}

// Forcing the second port of an exposed function names the one NIC it yields, not a second one.
func TestFindPassthroughNICsCollectsAForcedSiblingPortOnce(t *testing.T) {
	root := withSysfs(t)
	fakeIface(t, root, "eth0", "0000:43:00.0", "62", "identity", "00:00:5e:00:53:01")
	eth1 := fakeSibling(t, root, "eth1")
	require.NoError(t, os.WriteFile(filepath.Join(eth1, "perm_address"), []byte("00:00:5e:00:53:02\n"), 0o600))

	devices, err := FindPassthroughNICs(WithForcedInterface("eth1"))
	require.NoError(t, err)
	require.Len(t, devices.NICs, 1)
	assert.Equal(t, "eth1", devices.NICs[0].Interface)
	assert.Equal(t, "00:00:5e:00:53:02", devices.NICs[0].MAC)
	assert.False(t, devices.NICs[0].Forced, "the function is genuinely in passthrough")
}

// Forcing widens what is collected: a forced port with no usable MAC must not cost its function the
// NIC an unforced run reports.
func TestFindPassthroughNICsKeepsTheFunctionWhenTheForcedPortHasNoMAC(t *testing.T) {
	root := withSysfs(t)
	fakeIface(t, root, "eth0", "0000:43:00.0", "62", "identity", "00:00:5e:00:53:01")
	fakeSibling(t, root, "eth1")

	devices, err := FindPassthroughNICs(WithForcedInterface("eth1"))
	require.NoError(t, err)
	require.Len(t, devices.NICs, 1)
	assert.Equal(t, "eth0", devices.NICs[0].Interface)
	assert.Empty(t, devices.Undetermined)
}

// Forcing a representor forces its function, which is still joined on its port's MAC.
func TestFindPassthroughNICsJoinsAForcedRepresentorOnItsPort(t *testing.T) {
	root := withSysfs(t)
	fakeIface(t, root, "eth1", "0000:43:00.0", "62", "DMA-FQ", "00:00:5e:00:53:01")
	setPortName(t, filepath.Join(root, "class", "net", "eth1"), "p0")
	rep := fakeSibling(t, root, "eth0")
	setPortName(t, rep, "pf0vf0")
	require.NoError(t, os.WriteFile(filepath.Join(rep, "address"), []byte("00:00:5e:00:53:99\n"), 0o600))

	devices, err := FindPassthroughNICs(WithForcedInterface("eth0"))
	require.NoError(t, err)
	require.Len(t, devices.NICs, 1)
	assert.Equal(t, "eth1", devices.NICs[0].Interface)
	assert.Equal(t, "00:00:5e:00:53:01", devices.NICs[0].MAC)
	assert.True(t, devices.NICs[0].Forced)
}

// A forced representor with no port in view has nothing to join on: its own MAC is not the port's.
func TestFindPassthroughNICsReportsAForcedRepresentorWithNoPortAsUndetermined(t *testing.T) {
	root := withSysfs(t)
	fakeIface(t, root, "eth0", "0000:43:00.0", "62", "DMA", "")
	rep := filepath.Join(root, "class", "net", "eth0")
	setPortName(t, rep, "pf0vf0")
	require.NoError(t, os.WriteFile(filepath.Join(rep, "address"), []byte("00:00:5e:00:53:99\n"), 0o600))

	devices, err := FindPassthroughNICs(WithForcedInterface("eth0"))
	require.NoError(t, err)
	assert.Empty(t, devices.NICs)
	require.Len(t, devices.Undetermined, 1)
	assert.Contains(t, devices.Undetermined[0].Reason, "only switchdev representors")
}

// Only an exposed function owes a MAC, so a protected one showing only representors is simply clean.
func TestFindPassthroughNICsIgnoresAProtectedFunctionWithOnlyRepresentors(t *testing.T) {
	root := withSysfs(t)
	fakeIface(t, root, "eth0", "0000:43:00.0", "62", "DMA", "00:00:5e:00:53:99")
	setPortName(t, filepath.Join(root, "class", "net", "eth0"), "pf0vf0")

	devices, err := FindPassthroughNICs()
	require.NoError(t, err)
	assert.Empty(t, devices.NICs)
	assert.Empty(t, devices.Undetermined)
}

// A forced NIC with neither a group nor a MAC is still one PCI function, so one report.
func TestFindPassthroughNICsReportsAForcedFunctionOnce(t *testing.T) {
	root := withSysfs(t)
	fakeIface(t, root, "eth0", "0000:43:00.0", "", "", "")

	devices, err := FindPassthroughNICs(WithForcedInterface("eth0"))
	require.NoError(t, err)
	assert.Empty(t, devices.NICs, "no MAC to join on")
	require.Len(t, devices.Undetermined, 1)
	assert.Contains(t, devices.Undetermined[0].Reason, "no IOMMU group")
}
