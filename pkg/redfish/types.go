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

// The subsets of the DMTF Redfish resources this client reads.

type odataRef struct {
	ID string `json:"@odata.id"`
}

type collection struct {
	Members []odataRef `json:"Members"`
}

// ComponentIntegrity is the subset of the Redfish ComponentIntegrity resource this client reads.
type ComponentIntegrity struct {
	ID   string `json:"Id"`
	Type string `json:"ComponentIntegrityType"`
	// Actions carries the URIs the BMC advertises. The action name is vendor-chosen, so it is
	// read from here rather than assembled from the member id.
	Actions struct {
		TPMGetSignedMeasurements struct {
			Target string `json:"target"`
		} `json:"#ComponentIntegrity.TPMGetSignedMeasurements"`
		SPDMGetSignedMeasurements struct {
			Target string `json:"target"`
		} `json:"#ComponentIntegrity.SPDMGetSignedMeasurements"`
	} `json:"Actions"`
	TypeVersion        string `json:"ComponentIntegrityTypeVersion"`
	TargetComponentURI string `json:"TargetComponentURI"`
	SPDM               struct {
		IdentityAuthentication struct {
			// The BMC's own verdict, unsigned, so it is a claim and never proof.
			ResponderAuthentication struct {
				VerificationStatus string `json:"VerificationStatus"`
			} `json:"ResponderAuthentication"`
		} `json:"IdentityAuthentication"`
		MeasurementSet struct {
			MeasurementSpecification string `json:"MeasurementSpecification"`
			Measurements             []struct {
				MeasurementIndex         int    `json:"MeasurementIndex"`
				Measurement              string `json:"Measurement"`
				MeasurementType          string `json:"MeasurementType"`
				MeasurementHashAlgorithm string `json:"MeasurementHashAlgorithm"`
			} `json:"Measurements"`
		} `json:"MeasurementSet"`
	} `json:"SPDM"`
}

// Manager is the BMC's own inventory.
type Manager struct {
	Model           string `json:"Model"`
	FirmwareVersion string `json:"FirmwareVersion"`
	UUID            string `json:"UUID"`
}

// System is the platform inventory.
type System struct {
	Model        string `json:"Model"`
	SKU          string `json:"SKU"`
	SerialNumber string `json:"SerialNumber"`
	BiosVersion  string `json:"BiosVersion"`
	Manufacturer string `json:"Manufacturer"`
}

// NetworkAdapter is the device behind a ComponentIntegrity entry. SelfURI is filled in by the
// client, and can differ from the ComponentIntegrity's TargetComponentURI.
type NetworkAdapter struct {
	SelfURI      string `json:"-"`
	Name         string `json:"Name"`
	Model        string `json:"Model"`
	Manufacturer string `json:"Manufacturer"`
	PartNumber   string `json:"PartNumber"`
	SerialNumber string `json:"SerialNumber"`
	Location     struct {
		PartLocation struct {
			LocationType         string `json:"LocationType"`
			LocationOrdinalValue int    `json:"LocationOrdinalValue"`
		} `json:"PartLocation"`
	} `json:"Location"`
	Controllers []struct {
		FirmwarePackageVersion string `json:"FirmwarePackageVersion"`
	} `json:"Controllers"`
	Ports odataRef `json:"Ports"`
}

// NetworkPort is one port of a NetworkAdapter.
type NetworkPort struct {
	Ethernet struct {
		AssociatedMACAddresses []string `json:"AssociatedMACAddresses"`
	} `json:"Ethernet"`
}
