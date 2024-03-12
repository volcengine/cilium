// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/stats"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/volcengine/constant"
	"github.com/cilium/cilium/pkg/volcengine/eni/limits"
	eniTypes "github.com/cilium/cilium/pkg/volcengine/eni/types"
	"github.com/cilium/cilium/pkg/volcengine/utils"
)

// The following error constants represent the error conditions for
// CreateInterface without additional context embedded in order to make them
// usable for metrics accounting purposes.
const (
	errUnableToDetermineLimits   = "unable to determine limits"
	unableToDetermineLimits      = "unableToDetermineLimits"
	errUnableToGetSecurityGroups = "unable to get security groups"
	unableToGetSecurityGroups    = "unableToGetSecurityGroups"
	errUnableToCreateENI         = "unable to create ENI"
	unableToCreateENI            = "unableToCreateENI"
	errUnableToAttachENI         = "unable to attach ENI"
	unableToAttachENI            = "unableToAttachENI"
	unableToFindSubnet           = "unableToFindSubnet"
)

const (
	maxENIIPCreate = 10

	maxENIPerNode = 50
)

type ipamNodeActions interface {
	InstanceID() string
}

type Node struct {
	// node contains the general purpose fields of a node
	node ipamNodeActions

	// mutex protects members below this field
	mutex lock.RWMutex

	// enis is the list of ENIs attached to the node indexed by ENI ID.
	// Protected by Node.mutex.
	enis map[string]eniTypes.ENI

	// k8sObj is the CiliumNode custom resource representing the node
	k8sObj *v2.CiliumNode

	// manager is the ecs node manager responsible for this node
	manager *InstancesManager

	// instanceID of the node
	instanceID string
}

// NewNode returns a new Node
func NewNode(node *ipam.Node, k8sObj *v2.CiliumNode, mgr *InstancesManager) *Node {
	return &Node{
		node:       node,
		k8sObj:     k8sObj,
		manager:    mgr,
		instanceID: node.InstanceID(),
	}
}

// lockAllFuncCalls will lock in the period of all input func callings.
func (n *Node) lockAllFuncCalls(fs ...func()) func() {
	n.mutex.Lock()
	for i := range fs {
		fs[i]()
	}
	return n.mutex.Unlock
}

// rLockAllFuncCalls like lockAllFuncCalls but use read-only lock in the period of all input func callings.
func (n *Node) rLockAllFuncCalls(fs ...func()) func() {
	n.mutex.RLock()
	for i := range fs {
		fs[i]()
	}
	return n.mutex.RUnlock
}

// UpdatedNode is called when an update to the CiliumNode is received.
func (n *Node) UpdatedNode(obj *v2.CiliumNode) {
	defer n.lockAllFuncCalls()()
	n.k8sObj = obj
}

// PopulateStatusFields fills in the status field of the CiliumNode custom
// resource with Volcengine ENI specific information
func (n *Node) PopulateStatusFields(resource *v2.CiliumNode) {
	resource.Status.Volcengine.ENIS = make(map[string]eniTypes.ENI)

	n.manager.ForeachInstance(n.node.InstanceID(),
		func(_, interfaceID string, rev ipamTypes.InterfaceRevision) error {
			e, ok := rev.Resource.(*eniTypes.ENI)
			if ok {
				resource.Status.Volcengine.ENIS[interfaceID] = *e.DeepCopy()
			}
			return nil
		})
}

// backOffInOrder store back off funcs which will be called in order for operations back off
func (n *Node) backOffInOrder(fs ...func() error) error {
	for i := range fs {
		if err := fs[i](); err != nil {
			return err
		}
	}
	return nil
}

// CreateInterface creates an additional interface with the instance and
// attaches it to the instance as specified by the CiliumNode. neededAddresses
// of secondary IPs are assigned to the interface up to the maximum number of
// addresses as allowed by the instance.
func (n *Node) CreateInterface(ctx context.Context, allocation *ipam.AllocationAction, scopedLog *logrus.Entry) (int, string, error) {
	limit, available := n.getLimits()
	if !available {
		return 0, unableToDetermineLimits, fmt.Errorf(errUnableToDetermineLimits)
	}

	var rsc v2.CiliumNode
	n.rLockAllFuncCalls(func() { rsc = *n.k8sObj })()

	// Must allocate secondary ENI IPs as needed, up to ENI instance limit
	toAllocate := min(allocation.MaxIPsToAllocate, limit.IPv4, maxENIIPCreate) // in first alloc no more than 10
	// Validate whether request has already been fulfilled in the meantime
	if toAllocate < 1 {
		return 0, "", nil
	}

	subnet := n.manager.FindSuitableSubnet(rsc.Spec.Volcengine, toAllocate)
	if subnet == nil {
		return 0,
			unableToFindSubnet,
			fmt.Errorf(
				"no matching subnet available for interface creation (VPC=%s AZ=%s SubnetIDs=%v SubnetTags=%s",
				rsc.Spec.Volcengine.VPCID,
				rsc.Spec.Volcengine.AvailabilityZone,
				rsc.Spec.Volcengine.SubnetIDs,
				rsc.Spec.Volcengine.SubnetTags,
			)
	}
	allocation.PoolID = ipamTypes.PoolID(subnet.ID)

	securityGroupIDs, err := n.getSecurityGroupIDs(ctx, rsc.Spec.Volcengine)
	if err != nil {
		return 0,
			unableToGetSecurityGroups,
			fmt.Errorf("%s %s", errUnableToGetSecurityGroups, err)
	}

	scopedLog = scopedLog.WithFields(logrus.Fields{
		constant.LogFieldSecurityGroupIDs: securityGroupIDs,
		constant.LogFieldSubnetID:         subnet.ID,
		constant.LogFieldAddresses:        toAllocate,
	})
	scopedLog.Info("No more IPs available, creating new ENI")

	instanceID := n.node.InstanceID()

	defer n.lockAllFuncCalls()()
	index, err := n.allocENIIndex()
	if err != nil {
		scopedLog.WithField(constant.LogFieldInstanceID, instanceID).Error(err)
		return 0, "", err
	}
	eniID, eni, err := n.manager.api.CreateNetworkInterface(ctx, toAllocate-1, subnet.ID, securityGroupIDs,
		utils.FillTagWithENIIndex(map[string]string{}, index))
	if err != nil {
		return 0, unableToCreateENI, fmt.Errorf("%s %s", errUnableToCreateENI, err)
	}

	scopedLog = scopedLog.WithField(constant.LogFieldENID, eniID)
	scopedLog.Info("Created new ENI")

	if subnet.CIDR != nil {
		eni.Subnet.CIDRBlock = subnet.CIDR.String()
	}

	backOffs := []func() error{func() error {
		err := n.manager.api.DeleteNetworkInterface(ctx, eniID)
		if err != nil {
			scopedLog.Errorf("Failed to release ENI after failure to attach, %s", err.Error())
		}
		return err
	}}

	err = n.manager.api.AttachNetworkInterface(ctx, instanceID, eniID)
	if err != nil {
		_ = n.backOffInOrder(backOffs...)
		return 0, unableToAttachENI, fmt.Errorf("%s %s", errUnableToAttachENI, err)
	}
	_, err = n.manager.api.WaitENIAttached(ctx, eniID)
	if err != nil {
		_ = n.backOffInOrder(backOffs...)
		return 0, unableToAttachENI, fmt.Errorf("%s %s", errUnableToAttachENI, err)
	}

	n.enis[eniID] = *eni
	scopedLog.Info("Attached ENI to instance")

	// Add the information of the created ENI to the instances manager
	n.manager.UpdateENI(instanceID, eni)
	return toAllocate, "", nil
}

// ResyncInterfacesAndIPs is called to retrieve and ENIs and IPs as known to
// the volcengine API and return them
func (n *Node) ResyncInterfacesAndIPs(ctx context.Context, scopedLog *logrus.Entry) (allocations ipamTypes.AllocationMap, stats stats.InterfaceStats, err error) {
	limit, available := n.getLimits()
	if !available {
		return allocations, stats, fmt.Errorf(errUnableToDetermineLimits)
	}

	// During preparation of IP allocations, all addresses of the primary NIC
	// (and the primary ip address of the other NICs) are not considered
	// for allocation, so we don't need to consider it for capacity calculation.
	usePrimaryAddress := n.k8sObj.Spec.Volcengine.EnableUsePrimaryAddress()
	availableIPv4AddressNumber := limit.IPv4
	if !usePrimaryAddress {
		// exclude the primary address of every NIC
		availableIPv4AddressNumber -= 1
	}
	stats.NodeCapacity = limit.IPv4 * (limit.Adapters - 1)

	instanceID := n.node.InstanceID()

	defer n.lockAllFuncCalls()()
	n.enis = make(map[string]eniTypes.ENI)

	n.manager.ForeachInstance(instanceID,
		func(_, _ string, rev ipamTypes.InterfaceRevision) error {
			e, ok := rev.Resource.(*eniTypes.ENI)
			if !ok {
				return nil
			}

			n.enis[e.NetworkInterfaceID] = *e
			if e.Type == eniTypes.ENITypePrimary {
				return nil
			}

			if availableIPv4AddressNumber > len(e.PrivateIPSets) {
				stats.RemainingAvailableInterfaceCount++
			}

			for _, ip := range e.PrivateIPSets {
				if !usePrimaryAddress && ip.Primary {
					// the primary address of every NIC will be reserved when disable UsePrimaryAddress
					continue
				}
				allocations[ip.PrivateIpAddress] = ipamTypes.AllocationIP{Resource: e.NetworkInterfaceID}
			}

			return nil
		})
	eniUsedCount := len(n.enis)

	// An ECS instance has at least one ENI attached, no ENI found implies instance not found.
	if eniUsedCount < 1 {
		scopedLog.Warning("Instance not found! Please delete corresponding cilium node if instance has already been deleted.")
		return nil, stats, fmt.Errorf("unable to retrieve ENIs")
	}

	stats.RemainingAvailableInterfaceCount += limit.Adapters - eniUsedCount
	return allocations, stats, nil
}

// PrepareIPAllocation returns the number of ENI IPs and interfaces that can be
// allocated/created.
func (n *Node) PrepareIPAllocation(scopedLog *logrus.Entry) (*ipam.AllocationAction, error) {
	limit, available := n.getLimits()
	if !available {
		return nil, fmt.Errorf(errUnableToDetermineLimits)
	}

	a := &ipam.AllocationAction{}
	mostFreeOne := struct {
		eniID           string
		availableOneENI int
		subnet          *ipamTypes.Subnet
	}{
		subnet: &ipamTypes.Subnet{},
	}

	defer n.lockAllFuncCalls()()

	for eniID, e := range n.enis {
		if e.Type != eniTypes.ENITypeSecondary {
			continue
		}
		scopedLog.WithFields(logrus.Fields{
			constant.LogFieldENID:      e.NetworkInterfaceID,
			constant.LogFieldIPv4Limit: limit.IPv4,
			constant.LogFieldAllocated: len(e.PrivateIPSets),
		}).Debug("Considering ENI for allocation")

		// limit
		availableOnENI := max(limit.IPv4-len(e.PrivateIPSets), 0)
		if availableOnENI < 1 {
			continue
		}
		a.InterfaceCandidates++
		scopedLog.WithFields(logrus.Fields{
			constant.LogFieldENID:           e.NetworkInterfaceID,
			constant.LogFieldAvailableOnENI: availableOnENI,
		}).Debug("ENI has IPs available")

		if subnet := n.manager.GetSubnet(e.Subnet.SubnetID); subnet != nil {
			// find the eni have the most free subnet all over the ENIs
			if len(a.InterfaceID) < 1 && subnet.AvailableAddresses > mostFreeOne.subnet.AvailableAddresses {
				mostFreeOne.eniID = eniID
				mostFreeOne.availableOneENI = availableOnENI
				mostFreeOne.subnet = subnet
			}
		}
	}

	scopedLog.WithFields(logrus.Fields{
		constant.LogFieldSubnetID:           mostFreeOne.subnet.ID,
		constant.LogFieldAvailableAddresses: mostFreeOne.subnet.AvailableAddresses,
	}).Debug("Subnet has IPs available")

	a.InterfaceID = mostFreeOne.eniID
	a.PoolID = ipamTypes.PoolID(mostFreeOne.subnet.ID)
	a.AvailableForAllocation = min(mostFreeOne.subnet.AvailableAddresses, mostFreeOne.availableOneENI)

	a.EmptyInterfaceSlots = limit.Adapters - len(n.enis)
	return a, nil
}

// AllocateIPs performs the ENI allocation operation
func (n *Node) AllocateIPs(ctx context.Context, a *ipam.AllocationAction) error {
	_, err := n.manager.api.AssignPrivateIPAddresses(ctx, a.InterfaceID, a.AvailableForAllocation)
	return err
}

// PrepareIPRelease prepares the release of ENI IPs.
func (n *Node) PrepareIPRelease(excessIPs int, scopedLog *logrus.Entry) *ipam.ReleaseAction {
	r := &ipam.ReleaseAction{}

	defer n.lockAllFuncCalls()()

	// Iterate over ENIs on this node, select the ENI with the most
	// addresses available for release
	for key, e := range n.enis {
		if e.Type != eniTypes.ENITypeSecondary {
			continue
		}
		scopedLog.WithFields(logrus.Fields{
			constant.LogFieldENID:               e.NetworkInterfaceID,
			constant.LogFieldUsedAddressesCount: len(e.PrivateIPSets),
		}).Debug("Considering ENI for IP release")

		// Count free IP addresses on this ENI
		ipsOnENI := n.k8sObj.Status.Volcengine.ENIS[e.NetworkInterfaceID].PrivateIPSets
		freeIpsOnENI := make([]string, 0, len(ipsOnENI))
		for _, ip := range ipsOnENI {
			// exclude primary IPs
			if ip.Primary {
				continue
			}
			_, used := n.k8sObj.Status.IPAM.Used[ip.PrivateIpAddress]
			if !used {
				freeIpsOnENI = append(freeIpsOnENI, ip.PrivateIpAddress)
			}
		}
		freeOnENICount := len(freeIpsOnENI)

		if freeOnENICount < 1 {
			continue
		}

		scopedLog.WithFields(logrus.Fields{
			constant.LogFieldENID:           e.NetworkInterfaceID,
			constant.LogFieldExcessIPs:      excessIPs,
			constant.LogFieldFreeOnENICount: freeOnENICount,
		}).Debug("ENI has unused IPs that can be released")
		maxReleaseOnENI := min(freeOnENICount, excessIPs)

		r.InterfaceID = key
		r.PoolID = ipamTypes.PoolID(e.VPC.VPCID)
		r.IPsToRelease = freeIpsOnENI[:maxReleaseOnENI]
	}

	return r
}

// ReleaseIPs performs the ENI IP release operation
func (n *Node) ReleaseIPs(ctx context.Context, r *ipam.ReleaseAction) error {
	return n.manager.api.UnassignPrivateIPAddresses(ctx, r.InterfaceID, r.IPsToRelease)
}

// GetMaximumAllocatableIPv4 returns the maximum number of IPv4 addresses
// that can be allocated to the instance
func (n *Node) GetMaximumAllocatableIPv4() int {
	defer n.rLockAllFuncCalls()()

	// Retrieve limit for the instance type
	limit, available := n.getLimitsLocked()
	if !available {
		return 0
	}

	// Return the maximum number of IP addresses allocatable on the instance
	// reserve Primary eni
	// (and primary ip address of the other if disabled UsePrimaryAddress).
	availableIPv4AddressNumber := limit.IPv4
	if !n.k8sObj.Spec.Volcengine.EnableUsePrimaryAddress() {
		availableIPv4AddressNumber -= 1
	}
	return (limit.Adapters - 1) * availableIPv4AddressNumber
}

// GetMinimumAllocatableIPv4 returns the minimum number of IPv4 addresses that
// must be allocated to the instance.
func (n *Node) GetMinimumAllocatableIPv4() int {
	var reservedNumber int
	if !n.k8sObj.Spec.Volcengine.EnableUsePrimaryAddress() {
		reservedNumber++
	}
	return defaults.IPAMPreAllocation - reservedNumber
}

func (n *Node) loggerLocked() *logrus.Entry {
	if n == nil || n.instanceID == "" {
		return log
	}

	return log.WithField(constant.LogFieldInstanceID, n.instanceID)
}

func (n *Node) IsPrefixDelegated() bool {
	return false
}

func (n *Node) GetUsedIPWithPrefixes() int {
	if n.k8sObj == nil {
		return 0
	}
	return len(n.k8sObj.Status.IPAM.Used)
}

// getLimits returns the interface and IP limits of this node
func (n *Node) getLimits() (ipamTypes.Limits, bool) {
	defer n.rLockAllFuncCalls()()
	return n.getLimitsLocked()
}

// getLimitsLocked is the same function as getLimits, but assumes the n.mutex
// is read locked.
func (n *Node) getLimitsLocked() (ipamTypes.Limits, bool) {
	return limits.Get(n.k8sObj.Spec.Volcengine.InstanceType)
}

func (n *Node) getSecurityGroupIDs(ctx context.Context, eniSpec eniTypes.Spec) ([]string, error) {
	// Volcengine ENI must have at least one security group
	// 1. use security groups defined by user
	// 2. use security groups used by primary ENI (eth0)

	if len(eniSpec.SecurityGroups) > 0 {
		return eniSpec.SecurityGroups, nil
	}

	if len(eniSpec.SecurityGroupTags) > 0 {
		securityGroups := n.manager.FindSecurityGroupsByTags(eniSpec.VPCID, eniSpec.SecurityGroupTags)
		if len(securityGroups) < 1 {
			n.loggerLocked().WithFields(logrus.Fields{
				"vpcID": eniSpec.VPCID,
				"tags":  eniSpec.SecurityGroupTags,
			}).Warn("No security groups match required VPC ID and tags, using primary ENI's security groups")
		} else {
			groups := make([]string, 0, len(securityGroups))
			for _, secGroup := range securityGroups {
				groups = append(groups, secGroup.ID)
			}
			return groups, nil
		}
	}

	var securityGroups []string

	n.manager.ForeachInstance(n.node.InstanceID(),
		func(_, _ string, rev ipamTypes.InterfaceRevision) error {
			e, ok := rev.Resource.(*eniTypes.ENI)
			if ok && e.Type == eniTypes.ENITypePrimary {
				securityGroups = make([]string, len(e.SecurityGroupIds))
				copy(securityGroups, e.SecurityGroupIds)
			}
			return nil
		})

	if len(securityGroups) < 1 {
		return nil, fmt.Errorf("failed to get security group ids")
	}

	return securityGroups, nil
}

// allocENIIndex will alloc a monotonically increased index for each ENI on this instance.
// The index generated the first time this ENI is created and stored in ENI.Tags.
func (n *Node) allocENIIndex() (int, error) {
	// alloc index for each created ENI
	used := make([]bool, maxENIPerNode)
	for _, v := range n.enis {
		index := utils.GetENIIndexFromTags(v.Tags)
		if index > maxENIPerNode || index < 0 {
			return 0, fmt.Errorf("ENI index(%d) is out of range", index)
		}
		used[index] = true
	}
	// ECS has at least 1 ENI, 0 is reserved for eth0
	for i := 1; i < maxENIPerNode; i++ {
		if !used[i] {
			return i, nil
		}
	}
	return maxENIPerNode - 1, nil
}
