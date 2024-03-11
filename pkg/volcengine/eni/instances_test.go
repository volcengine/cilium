package eni

import (
	"context"
	"net"
	"testing"

	"github.com/cilium/cilium/pkg/cidr"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	eniTypes "github.com/cilium/cilium/pkg/volcengine/eni/types"
	"github.com/cilium/cilium/pkg/volcengine/types"
	"github.com/stretchr/testify/assert"
)

// ENIMap is a map of ENI interfaced indexed by ENI ID
type ENIMap map[string]*eniTypes.ENI

type MockVolcengineAPI struct {
	subnets        map[string]*ipamTypes.Subnet
	vpcs           map[string]*ipamTypes.VirtualNetwork
	enis           map[string]ENIMap
	securityGroups map[string]*types.SecurityGroup
}

func NewMockVolcengineAPI(subnets map[string]*ipamTypes.Subnet, vpcs map[string]*ipamTypes.VirtualNetwork, enis map[string]ENIMap, securityGroups map[string]*types.SecurityGroup) VolcengineAPI {
	api := &MockVolcengineAPI{
		subnets:        subnets,
		vpcs:           vpcs,
		securityGroups: securityGroups,
		enis:           enis,
	}
	return api
}

func (m *MockVolcengineAPI) GetInstance(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap, instanceID string) (*ipamTypes.Instance, error) {
	instance := &ipamTypes.Instance{}
	instance.Interfaces = map[string]ipamTypes.InterfaceRevision{}

	enis := m.enis[instanceID]
	if enis == nil {
		return instance, nil
	}

	for _, eni := range enis {
		if vpcs != nil {
			if vpc, ok := vpcs[eni.VPC.VPCID]; ok {
				eni.VPC.CIDRBlock = vpc.PrimaryCIDR
			}
		}
		if subnets != nil {
			if subnet, ok := subnets[eni.Subnet.SubnetID]; ok {
				eni.Subnet.CIDRBlock = subnet.CIDR.String()
			}
		}
		eniRevision := ipamTypes.InterfaceRevision{
			Resource: eni.DeepCopy(),
		}
		instance.Interfaces[eni.NetworkInterfaceID] = eniRevision
	}
	return instance, nil
}

func (m *MockVolcengineAPI) GetInstances(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap) (*ipamTypes.InstanceMap, error) {
	instances := ipamTypes.NewInstanceMap()

	for instanceID, eniMap := range m.enis {
		for _, eni := range eniMap {
			if vpcs != nil {
				if vpc, ok := vpcs[eni.VPC.VPCID]; ok {
					eni.VPC.CIDRBlock = vpc.PrimaryCIDR
				}
			}
			if subnets != nil {
				if subnet, ok := subnets[eni.Subnet.SubnetID]; ok {
					eni.Subnet.CIDRBlock = subnet.CIDR.String()
				}
			}
			eniRevision := ipamTypes.InterfaceRevision{
				Resource: eni.DeepCopy(),
			}
			instances.Update(instanceID, eniRevision)
		}
	}
	return instances, nil
}

func (m *MockVolcengineAPI) GetSecurityGroups(ctx context.Context) (types.SecurityGroupMap, error) {
	securityGroups := types.SecurityGroupMap{}

	for _, sg := range m.securityGroups {
		securityGroups[sg.ID] = sg.DeepCopy()
	}
	return securityGroups, nil
}

func (m *MockVolcengineAPI) GetSubnets(ctx context.Context) (ipamTypes.SubnetMap, error) {
	subnets := ipamTypes.SubnetMap{}

	for _, s := range m.subnets {
		subnets[s.ID] = s.DeepCopy()
	}
	return subnets, nil
}

func (m *MockVolcengineAPI) GetVPCs(ctx context.Context) (ipamTypes.VirtualNetworkMap, error) {
	vpcs := ipamTypes.VirtualNetworkMap{}

	for _, v := range m.vpcs {
		vpcs[v.ID] = v.DeepCopy()
	}
	return vpcs, nil
}

var (
	_, cidrSubnet1, _ = net.ParseCIDR("10.0.1.0/24")
	_, cidrSubnet2, _ = net.ParseCIDR("10.0.2.0/24")
	subnets           = map[string]*ipamTypes.Subnet{
		"subnet-1": {
			ID:                 "subnet-1",
			AvailableAddresses: 10,
			VirtualNetworkID:   "vpc-1",
			CIDR:               cidr.NewCIDR(cidrSubnet1),
			AvailabilityZone:   "cn-beijing-a",
			Tags: map[string]string{
				"subnet-name": "subnet-1",
			},
		},
		"subnet-2": {
			ID:                 "subnet-2",
			AvailableAddresses: 20,
			VirtualNetworkID:   "vpc-1",
			CIDR:               cidr.NewCIDR(cidrSubnet2),
			AvailabilityZone:   "cn-beijing-b",
			Tags: map[string]string{
				"subnet-name": "subnet-2",
			},
		},
	}

	vpcs = map[string]*ipamTypes.VirtualNetwork{
		"vpc-1": {
			ID:          "vpc-1",
			PrimaryCIDR: "10.0.0.0/16",
		},
	}

	securityGroups = map[string]*types.SecurityGroup{
		"sg-1": {
			ID:    "sg-1",
			VPCID: "vpc-1",
			Tags:  map[string]string{"sg-name": "sg-1"},
		},
		"sg-2": {
			ID:    "sg-2",
			VPCID: "vpc-1",
			Tags:  map[string]string{"sg-name": "sg-2"},
		},
	}

	enis = map[string]ENIMap{
		"instance-1": {
			"eni-1": {
				NetworkInterfaceID: "eni-1",
				Subnet:             eniTypes.Subnet{SubnetID: "subnet-1"},
				VPC:                eniTypes.VPC{VPCID: "vpc-1"},
				SecurityGroupIds:   []string{"sg-1", "sg-2"},
			},
		},
		"instance-2": {
			"eni-2": {
				NetworkInterfaceID: "eni-2",
				Subnet:             eniTypes.Subnet{SubnetID: "subnet-2"},
				VPC:                eniTypes.VPC{VPCID: "vpc-1"},
				SecurityGroupIds:   []string{"sg-1", "sg-2"},
			},
		},
	}
)

func TestResync(t *testing.T) {
	api := NewMockVolcengineAPI(subnets, vpcs, enis, securityGroups)
	// Sync resources from the Volcengine API
	mngr := NewInstancesManager(api)
	startTime := mngr.Resync(context.Background())
	assert.False(t, startTime.IsZero())
	cachedInstances := []string{}
	mngr.ForeachInstance("", func(instanceID, interfaceID string, rev ipamTypes.InterfaceRevision) error {
		cachedInstances = append(cachedInstances, instanceID)
		return nil
	})
	assert.ElementsMatch(t, []string{"instance-1", "instance-2"}, cachedInstances)

	t.Run("FindSubnetByIDs", func(t *testing.T) {
		bestSubnet := mngr.FindSubnetByIDs("vpc-1", "cn-beijing-a", nil, 0)
		assert.Nil(t, bestSubnet)

		bestSubnet = mngr.FindSubnetByIDs("vpc-1", "cn-beijing-a", []string{"subnet-1"}, 0)
		assert.Equal(t, subnets["subnet-1"], bestSubnet)

		bestSubnet = mngr.FindSubnetByIDs("vpc-1", "cn-beijing-a", []string{"subnet-1", "subnet-2"}, 0)
		assert.Equal(t, subnets[bestSubnet.ID], bestSubnet)
	})

	t.Run("FindSubnetByTags", func(t *testing.T) {
		bestSubnet := mngr.FindSubnetByTags("vpc-1", "cn-beijing-a", nil)
		assert.Equal(t, subnets["subnet-1"], bestSubnet)

		expectedTags := ipamTypes.Tags{"subnet-name": "subnet-1"}
		bestSubnet = mngr.FindSubnetByTags("vpc-1", "cn-beijing-a", expectedTags)
		assert.Equal(t, subnets["subnet-1"], bestSubnet)
	})

	t.Run("FindSecurityGroupsByIDs", func(t *testing.T) {
		foundSGs := mngr.FindSecurityGroupsByIDs("vpc-1", nil)
		assert.Empty(t, foundSGs)

		expectedSecurityGroupIDs := []string{"sg-1", "sg-2"}
		foundSGs = mngr.FindSecurityGroupsByIDs("vpc-1", expectedSecurityGroupIDs)
		assert.Equal(t, 2, len(foundSGs))
		for _, sg := range foundSGs {
			assert.Equal(t, securityGroups[sg.ID], sg)
		}
	})

	t.Run("FindSecurityGroupsByTags", func(t *testing.T) {
		foundSGs := mngr.FindSecurityGroupsByTags("vpc-1", nil)
		assert.Equal(t, 2, len(foundSGs))
		for _, sg := range foundSGs {
			assert.Equal(t, securityGroups[sg.ID], sg)
		}

		expectedTags := ipamTypes.Tags{"sg-name": "sg-1"}
		foundSGs = mngr.FindSecurityGroupsByTags("vpc-1", expectedTags)
		assert.Equal(t, 1, len(foundSGs))
		assert.Equal(t, securityGroups["sg-1"], foundSGs[0])
	})
}

func TestInstanceSync(t *testing.T) {
	api := NewMockVolcengineAPI(subnets, vpcs, enis, securityGroups)
	targetInstanceID := "instance-1"
	// Sync resources from the Volcengine API
	mngr := NewInstancesManager(api)
	startTime := mngr.InstanceSync(context.Background(), targetInstanceID)
	assert.False(t, startTime.IsZero())
	cachedInstances := []string{}
	mngr.ForeachInstance(targetInstanceID, func(instanceID, interfaceID string, rev ipamTypes.InterfaceRevision) error {
		cachedInstances = append(cachedInstances, instanceID)
		return nil
	})
	assert.ElementsMatch(t, []string{targetInstanceID}, cachedInstances)
}
