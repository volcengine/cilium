// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"context"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/ipam"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/volcengine/api"
	"github.com/cilium/cilium/pkg/volcengine/constant"
	eniTypes "github.com/cilium/cilium/pkg/volcengine/eni/types"
	"github.com/cilium/cilium/pkg/volcengine/types"
)

// InstancesManager maintains the state of the instances. It must be kept up
// to date by calling Resync() regularly.
type InstancesManager struct {
	mutex          lock.RWMutex
	resyncLock     lock.RWMutex
	instances      *ipamTypes.InstanceMap
	subnets        ipamTypes.SubnetMap
	vpcs           ipamTypes.VirtualNetworkMap
	securityGroups types.SecurityGroupMap
	api            api.VolcengineAPI
}

// NewInstancesManager creates a new InstancesManager.
func NewInstancesManager(api api.VolcengineAPI) *InstancesManager {
	return &InstancesManager{
		instances: ipamTypes.NewInstanceMap(),
		api:       api,
	}
}

// CreateNode is called on discovery of a new node and retusn the ENI node
// allocation implementation for the new node.
func (m *InstancesManager) CreateNode(obj *v2.CiliumNode, node *ipam.Node) ipam.NodeOperations {
	return NewNode(node, obj, m)
}

// DeleteInstance deletes instance by given instanceID.
func (m *InstancesManager) DeleteInstance(instanceID string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.instances.Delete(instanceID)
}

// GetPoolQuota returns the number of available IPs in all IP pools.
func (m *InstancesManager) GetPoolQuota() ipamTypes.PoolQuotaMap {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	pool := ipamTypes.PoolQuotaMap{}
	for subnetID, subnet := range m.subnets {
		pool[ipamTypes.PoolID(subnetID)] = ipamTypes.PoolQuota{
			AvailabilityZone: subnet.AvailabilityZone,
			AvailableIPs:     subnet.AvailableAddresses,
		}
	}
	return pool
}

// HasInstance returns whether the instance is in instances.
func (m *InstancesManager) HasInstance(instanceID string) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.instances.Exists(instanceID)
}

// Resync fetches the list of ECS instances and subnets and updates the local
// cache. It retruns the time when the resync was started or time.Time{} if it
// did not complete.
func (m *InstancesManager) Resync(ctx context.Context) time.Time {
	m.resyncLock.Lock()
	defer m.resyncLock.Unlock()
	return m.resync(ctx, "")
}

// InstanceSync fetches the ECS instance by given instanceID and updates the
// local cache. It retruns the time when the resync was started or time.Time{}
// if it did not complete.
func (m *InstancesManager) InstanceSync(ctx context.Context, instanceID string) time.Time {
	// Allow sync multiple nodes in parallel.
	m.resyncLock.RLock()
	defer m.resyncLock.RUnlock()
	return m.resync(ctx, instanceID)
}

func (m *InstancesManager) resync(ctx context.Context, instanceID string) time.Time {
	resyncStart := time.Now()

	vpcs, err := m.api.GetVPCs(ctx)
	if err != nil {
		log.WithError(err).Warning("Unable to synchronize VPC list")
		return time.Time{}
	}

	subnets, err := m.api.GetSubnets(ctx)
	if err != nil {
		log.WithError(err).Warning("Unable to synchronize subnet list")
		return time.Time{}
	}

	securityGroups, err := m.api.GetSecurityGroups(ctx)
	if err != nil {
		log.WithError(err).Warning("Unable to synchronize security group list")
		return time.Time{}
	}

	if instanceID == "" {
		instances, err := m.api.GetInstances(ctx, vpcs, subnets)
		if err != nil {
			log.WithError(err).Warning("Unable to synchronize instances list")
			return time.Time{}
		}

		log.WithFields(logrus.Fields{
			"numInstances":      instances.NumInstances(),
			"numVPCs":           len(vpcs),
			"numSubnets":        len(subnets),
			"numSecurityGroups": len(securityGroups),
		}).Info("Synchronized ENI information")

		m.mutex.Lock()
		defer m.mutex.Unlock()
		m.instances = instances
	} else {
		instance, err := m.api.GetInstance(ctx, vpcs, subnets, instanceID)
		if err != nil {
			log.WithError(err).WithField(constant.LogFieldENID, instanceID).Warning("Unable to synchronize instance")
			return time.Time{}
		}

		log.WithFields(logrus.Fields{
			constant.LogFieldInstanceID: instanceID,
			"numVPCs":                   len(vpcs),
			"numSubnets":                len(subnets),
			"numSecurityGroups":         len(securityGroups),
		}).Info("Synchronized ENI information for the corresponding instance")

		m.mutex.Lock()
		defer m.mutex.Unlock()
		m.instances.UpdateInstance(instanceID, instance)
	}
	m.vpcs = vpcs
	m.subnets = subnets
	m.securityGroups = securityGroups

	return resyncStart
}

// UpdateENI updates the ENI definition for the given instance. If the ENI
// is already present, it will be updated, otherwise it will be added.
func (m *InstancesManager) UpdateENI(instanceID string, eni *eniTypes.ENI) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	eniRevision := ipamTypes.InterfaceRevision{Resource: eni}
	m.instances.Update(instanceID, eniRevision)
}

// ForeachInstance will iterate over each instance inside `instances`, and call
// `fn`. This function is read-locked for the entire execution.
func (m *InstancesManager) ForeachInstance(instanceID string, fn ipamTypes.InterfaceIterator) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	_ = m.instances.ForeachInterface(instanceID, fn)
}

func (m *InstancesManager) FindSuitableSubnet(spec eniTypes.Spec, toAllocate int) *ipamTypes.Subnet {
	if len(spec.SubnetIDs) > 0 {
		return m.FindSubnetByIDs(spec.VPCID, spec.AvailabilityZone, spec.SubnetIDs, toAllocate)
	}
	var bestSubnet *ipamTypes.Subnet
	for _, subnet := range m.subnets {
		if subnet.VirtualNetworkID == spec.VPCID && subnet.AvailabilityZone == spec.AvailabilityZone {
			if subnet.AvailableAddresses < toAllocate {
				continue
			}
			if bestSubnet == nil || subnet.AvailableAddresses > bestSubnet.AvailableAddresses {
				bestSubnet = subnet
			}
		}
	}
	return bestSubnet
}

// GetSubnet returns the subnet by subnet ID
//
// The returned subnet is immutable, so it can be safely accessed
func (m *InstancesManager) GetSubnet(subnetID string) *ipamTypes.Subnet {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return m.subnets[subnetID]
}

// FindSubnetByIDs returns the subnet with the most available addresses matching VPC ID,
// availability zone within a provided list of subnet IDs.
//
// The returned subnet is assumed to be immutable and should not be modified.
func (m *InstancesManager) FindSubnetByIDs(vpcID, availabilityZone string, subnetIDs []string, toAllocate int) *ipamTypes.Subnet {
	var bestSubnet *ipamTypes.Subnet
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, curSubnetID := range subnetIDs {
		if subnet, ok := m.subnets[curSubnetID]; ok {
			if subnet.VirtualNetworkID == vpcID && subnet.AvailabilityZone == availabilityZone {
				if subnet.AvailableAddresses < toAllocate {
					continue
				}
				if bestSubnet == nil || subnet.AvailableAddresses > bestSubnet.AvailableAddresses {
					bestSubnet = subnet
				}
			}
		}
	}
	return bestSubnet
}

// FindSubnetByTags returns the subnet with the most available addresses matching VPC ID,
// availability zone and tags.
//
// The returned subnet is assumed to be immutable and should not be modified.
func (m *InstancesManager) FindSubnetByTags(vpcID, availabilityZone string, required ipamTypes.Tags) *ipamTypes.Subnet {
	var bestSubnet *ipamTypes.Subnet
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, s := range m.subnets {
		if s.VirtualNetworkID == vpcID && s.AvailabilityZone == availabilityZone {
			if s.AvailableAddresses > 0 && s.Tags.Match(required) {
				if bestSubnet == nil || s.AvailableAddresses > bestSubnet.AvailableAddresses {
					bestSubnet = s
				}
			}
		}
	}
	return bestSubnet
}

// FindSecurityGroupsByIDs returns the security groups matching the provided VPC ID and security group IDs.
func (m *InstancesManager) FindSecurityGroupsByIDs(vpcID string, securityGroupIDs []string) []*types.SecurityGroup {
	securityGroups := make([]*types.SecurityGroup, 0, len(securityGroupIDs))
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, sgID := range securityGroupIDs {
		if sg, ok := m.securityGroups[sgID]; ok && sg.VPCID == vpcID {
			securityGroups = append(securityGroups, sg)
		}
	}
	return securityGroups
}

// FindSecurityGroupsByTags returns the security groups matching the provided tags and VPC ID.
func (m *InstancesManager) FindSecurityGroupsByTags(vpcID string, required ipamTypes.Tags) []*types.SecurityGroup {
	var securityGroups []*types.SecurityGroup

	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, sg := range m.securityGroups {
		if sg.VPCID == vpcID && sg.Tags.Match(required) {
			securityGroups = append(securityGroups, sg)
		}
	}
	return securityGroups
}
